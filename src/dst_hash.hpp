#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace dst {

using Block8 = std::array<std::uint8_t, 8>;

Block8 ebcdic8(const std::string& ascii);
Block8 hash_password(const std::string& password, const std::string& user_id);
std::string hex_encode(const Block8& bytes);
Block8 hex_decode8(const std::string& hex);

}  // namespace dst
