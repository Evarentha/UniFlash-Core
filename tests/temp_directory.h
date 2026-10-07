/*
 * UniFlash-Core Test / Temporary Directory
 *
 * Creates and removes a unique temporary directory per test run.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UNIFLASH_TEST_TEMP_DIRECTORY_H
#define UNIFLASH_TEST_TEMP_DIRECTORY_H
#include <filesystem>
#include <random>
#include <stdexcept>

struct TempDirectory {
    std::filesystem::path path;
    TempDirectory() {
        std::random_device random;
        for(unsigned attempt=0;attempt<100;++attempt) {
            path=std::filesystem::temp_directory_path()/
                ("uniflash-test-"+std::to_string(random())+"-"+std::to_string(random()));
            std::error_code error;
            if(std::filesystem::create_directory(path,error)) return;
            if(error && error!=std::errc::file_exists) throw std::system_error(error);
        }
        throw std::runtime_error("cannot create unique test directory");
    }
    ~TempDirectory() { std::error_code ignored; std::filesystem::remove_all(path,ignored); }
};
#endif
