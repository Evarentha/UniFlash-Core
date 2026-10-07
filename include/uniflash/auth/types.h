#pragma once
#include <cstdint>
#include <expected>
#include <functional>
#include <span>
#include <stop_token>
#include <system_error>
#include <vector>
namespace uniflash::auth {
using Responder = std::function<std::expected<std::vector<uint8_t>,std::errc>(
    std::span<const uint8_t>,std::stop_token)>;
}
