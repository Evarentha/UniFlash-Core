/*
 * UniFlash-Core / Command Argument Parsing
 *
 * Splits and quotes command lines into tokens for the dispatcher.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <istream>
#include <string>
#include <string_view>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace uniflash::cli {
inline bool next_token(std::istream& in, std::string& out) {
    out.clear();
    in >> std::ws;
    if (in.peek() == std::char_traits<char>::eof()) return false;
    const char first = static_cast<char>(in.get());
    const auto space = [](int c) { return c==' ' || c=='\t' || c=='\r' || c=='\n'; };
    if (first == '\'' || first == '"') {
        bool closed = false;
        for (char c; in.get(c);) {
            if (c == first) { closed = true; break; }
            // Escape only quotes/backslashes inside quotes; Windows paths
            // retain every other backslash literally.
            if (c == '\\' && (in.peek() == first || in.peek() == '\\')) c = static_cast<char>(in.get());
            out += c;
        }
        if (!closed) throw std::invalid_argument("unterminated quoted argument");
        if (in.peek()!=std::char_traits<char>::eof() && !space(in.peek()))
            throw std::invalid_argument("expected whitespace after quoted argument");
    } else {
        out += first;
        while (in.peek()!=std::char_traits<char>::eof() && !space(in.peek())) out += static_cast<char>(in.get());
        if (out.find_first_of("\"'") != std::string::npos) throw std::invalid_argument("quote must start an argument");
    }
    if (out.find('\0') != std::string::npos) throw std::invalid_argument("NUL in argument");
    return true;
}
inline std::vector<std::string> parse_arguments(std::string_view line) {
    std::istringstream in{std::string(line)};
    std::vector<std::string> result;
    for (std::string word; next_token(in, word);) result.push_back(std::move(word));
    return result;
}
inline std::string quote_argument(std::string_view text) {
    std::string out="\"";
    for(char c:text) { if(c=='"' || c=='\\') out+='\\'; out+=c; }
    return out+'"';
}
}
