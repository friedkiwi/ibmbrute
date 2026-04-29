#include "dst_hash.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string_view>

namespace dst {

namespace {

constexpr int IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
};

constexpr int FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
};

constexpr int E[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
};

constexpr int P[32] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
};

constexpr int PC1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
};

constexpr int PC2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
};

constexpr int SHIFTS[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

constexpr std::uint8_t SBOX[8][64] = {
    {
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    },
    {
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    },
    {
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    },
    {
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    },
    {
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    },
    {
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    },
    {
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    },
    {
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    },
};

std::uint64_t load_be64(const Block8& bytes) {
    std::uint64_t value = 0;
    for (std::uint8_t b : bytes) {
        value = (value << 8) | b;
    }
    return value;
}

Block8 store_be64(std::uint64_t value) {
    Block8 out{};
    for (int i = 7; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(value & 0xffu);
        value >>= 8;
    }
    return out;
}

std::uint64_t permute(std::uint64_t input, const int* table, int count, int input_bits) {
    std::uint64_t output = 0;
    for (int i = 0; i < count; ++i) {
        output <<= 1;
        const int bit_index = input_bits - table[i];
        output |= (input >> bit_index) & 1ULL;
    }
    return output;
}

std::uint64_t rotate_left_28(std::uint64_t value, int shift) {
    value &= 0x0fffffffull;
    return ((value << shift) | (value >> (28 - shift))) & 0x0fffffffull;
}

std::uint32_t feistel(std::uint32_t half, std::uint64_t round_key) {
    const std::uint64_t expanded = permute(static_cast<std::uint64_t>(half) << 32, E, 48, 64);
    const std::uint64_t mixed = expanded ^ round_key;

    std::uint32_t substituted = 0;
    for (int box = 0; box < 8; ++box) {
        const int shift = 42 - box * 6;
        const std::uint8_t chunk = static_cast<std::uint8_t>((mixed >> shift) & 0x3fULL);
        const std::uint8_t row = static_cast<std::uint8_t>(((chunk & 0x20u) >> 4) | (chunk & 0x01u));
        const std::uint8_t col = static_cast<std::uint8_t>((chunk >> 1) & 0x0fu);
        const std::uint8_t value = SBOX[box][row * 16 + col];
        substituted = (substituted << 4) | value;
    }

    return static_cast<std::uint32_t>(permute(static_cast<std::uint64_t>(substituted) << 32, P, 32, 64));
}

std::array<std::uint64_t, 16> build_round_keys(const Block8& key) {
    const std::uint64_t raw = load_be64(key);
    const std::uint64_t pc1 = permute(raw, PC1, 56, 64);

    std::uint64_t c = (pc1 >> 28) & 0x0fffffffull;
    std::uint64_t d = pc1 & 0x0fffffffull;

    std::array<std::uint64_t, 16> round_keys{};
    for (int round = 0; round < 16; ++round) {
        c = rotate_left_28(c, SHIFTS[round]);
        d = rotate_left_28(d, SHIFTS[round]);
        const std::uint64_t cd = (c << 28) | d;
        round_keys[round] = permute(cd << 8, PC2, 48, 64);
    }
    return round_keys;
}

std::uint8_t to_cp037(unsigned char c) {
    switch (c) {
        case ' ': return 0x40;
        case '#': return 0x7b;
        case '@': return 0x7c;
        case '$': return 0x5b;
        case '_': return 0x6d;
        case '0': return 0xf0;
        case '1': return 0xf1;
        case '2': return 0xf2;
        case '3': return 0xf3;
        case '4': return 0xf4;
        case '5': return 0xf5;
        case '6': return 0xf6;
        case '7': return 0xf7;
        case '8': return 0xf8;
        case '9': return 0xf9;
        case 'A': return 0xc1;
        case 'B': return 0xc2;
        case 'C': return 0xc3;
        case 'D': return 0xc4;
        case 'E': return 0xc5;
        case 'F': return 0xc6;
        case 'G': return 0xc7;
        case 'H': return 0xc8;
        case 'I': return 0xc9;
        case 'J': return 0xd1;
        case 'K': return 0xd2;
        case 'L': return 0xd3;
        case 'M': return 0xd4;
        case 'N': return 0xd5;
        case 'O': return 0xd6;
        case 'P': return 0xd7;
        case 'Q': return 0xd8;
        case 'R': return 0xd9;
        case 'S': return 0xe2;
        case 'T': return 0xe3;
        case 'U': return 0xe4;
        case 'V': return 0xe5;
        case 'W': return 0xe6;
        case 'X': return 0xe7;
        case 'Y': return 0xe8;
        case 'Z': return 0xe9;
        case 'a': return 0x81;
        case 'b': return 0x82;
        case 'c': return 0x83;
        case 'd': return 0x84;
        case 'e': return 0x85;
        case 'f': return 0x86;
        case 'g': return 0x87;
        case 'h': return 0x88;
        case 'i': return 0x89;
        case 'j': return 0x91;
        case 'k': return 0x92;
        case 'l': return 0x93;
        case 'm': return 0x94;
        case 'n': return 0x95;
        case 'o': return 0x96;
        case 'p': return 0x97;
        case 'q': return 0x98;
        case 'r': return 0x99;
        case 's': return 0xa2;
        case 't': return 0xa3;
        case 'u': return 0xa4;
        case 'v': return 0xa5;
        case 'w': return 0xa6;
        case 'x': return 0xa7;
        case 'y': return 0xa8;
        case 'z': return 0xa9;
        default:
            throw std::runtime_error(std::string("unsupported ASCII character for cp037 encoding: ") +
                                     static_cast<char>(c));
    }
}

bool is_hex(std::string_view s) {
    return std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

std::uint8_t hex_value(char c) {
    if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(10 + c - 'a');
    if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(10 + c - 'A');
    throw std::runtime_error("invalid hex digit");
}

}  // namespace

Block8 ebcdic8(const std::string& ascii) {
    Block8 out{};
    const std::size_t count = std::min<std::size_t>(ascii.size(), out.size());
    for (std::size_t i = 0; i < count; ++i) {
        out[i] = to_cp037(static_cast<unsigned char>(ascii[i]));
    }
    for (std::size_t i = count; i < out.size(); ++i) {
        out[i] = 0x40;
    }
    return out;
}

// Corrected DST hash:  hash = DES_ECB(key=ebcdic8(user_id), plaintext=ebcdic8(password)).
//
// This orientation was originally documented backwards in findings.md.  All
// four IBM-default calibration pairs (QSECOFR/QSECOFR, QSRV/QSRV, etc.) had
// password == user_id, so DES's asymmetry between key and plaintext was
// invisible.  The error surfaced when sign-on on a real OS/400 rejected
// "QSDBOFQ" (a parity-equivalent of QSECOFR's password under PC-1) even
// though the prior formula said both should collide.  Under the corrected
// formula the password is the DES plaintext: every bit is significant, no
// LSB equivalence class, recovered plaintext is the literal operator input.
Block8 hash_password(const std::string& password, const std::string& user_id) {
    const Block8 key = ebcdic8(user_id);
    const Block8 block = ebcdic8(password);
    const auto round_keys = build_round_keys(key);

    std::uint64_t state = load_be64(block);
    state = permute(state, IP, 64, 64);

    std::uint32_t left = static_cast<std::uint32_t>(state >> 32);
    std::uint32_t right = static_cast<std::uint32_t>(state & 0xffffffffu);
    for (int round = 0; round < 16; ++round) {
        const std::uint32_t next_left = right;
        const std::uint32_t next_right = left ^ feistel(right, round_keys[round]);
        left = next_left;
        right = next_right;
    }

    const std::uint64_t preoutput = (static_cast<std::uint64_t>(right) << 32) | left;
    const std::uint64_t final_state = permute(preoutput, FP, 64, 64);
    return store_be64(final_state);
}

std::string hex_encode(const Block8& bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (std::uint8_t b : bytes) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0f]);
    }
    return out;
}

Block8 hex_decode8(const std::string& hex) {
    if (hex.size() != 16 || !is_hex(hex)) {
        throw std::runtime_error("expected a 16-character hexadecimal hash");
    }

    Block8 out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>((hex_value(hex[i * 2]) << 4) | hex_value(hex[i * 2 + 1]));
    }
    return out;
}

}  // namespace dst
