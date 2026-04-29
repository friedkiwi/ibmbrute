#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include "metal_backend.hpp"

#include <algorithm>
#include <limits>
#include <mutex>
#include <sstream>
#include <stdexcept>

namespace metal_backend {

namespace {

constexpr std::size_t kBatchSize = 8192;

const char* kMetalKernelSource = R"metal(
#include <metal_stdlib>
using namespace metal;

constant uchar IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
};

constant uchar FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
};

constant uchar E[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
};

constant uchar P[32] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
};

constant uchar PC1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
};

constant uchar PC2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
};

constant uchar SHIFTS[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

constant uchar SBOX[8][64] = {
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

inline ulong permute(ulong input, constant uchar* table, uint count, uint input_bits)
{
    ulong output = 0;
    for (uint i = 0; i < count; ++i) {
        output <<= 1;
        const uint bit_index = input_bits - uint(table[i]);
        output |= (input >> bit_index) & 1ul;
    }
    return output;
}

inline ulong load_be64(const device uchar* bytes)
{
    ulong value = 0;
    for (uint i = 0; i < 8; ++i) {
        value = (value << 8) | ulong(bytes[i]);
    }
    return value;
}

inline ulong rotate_left_28(ulong value, uint shift)
{
    value &= 0x0ffffffful;
    return ((value << shift) | (value >> (28 - shift))) & 0x0ffffffful;
}

inline uint feistel(uint half, thread const ulong* round_keys, uint round)
{
    const ulong expanded = permute(ulong(half) << 32, E, 48, 64);
    const ulong mixed = expanded ^ round_keys[round];

    uint substituted = 0;
    for (uint box = 0; box < 8; ++box) {
        const uint shift = 42 - (box * 6);
        const uchar chunk = uchar((mixed >> shift) & 0x3ful);
        const uchar row = uchar(((chunk & 0x20u) >> 4) | (chunk & 0x01u));
        const uchar col = uchar((chunk >> 1) & 0x0fu);
        const uchar value = SBOX[box][row * 16 + col];
        substituted = (substituted << 4) | uint(value);
    }

    return uint(permute(ulong(substituted) << 32, P, 32, 64));
}

inline ulong des_encrypt(ulong key, ulong block)
{
    thread ulong round_keys[16];

    const ulong pc1 = permute(key, PC1, 56, 64);
    ulong c = (pc1 >> 28) & 0x0ffffffful;
    ulong d = pc1 & 0x0ffffffful;

    for (uint round = 0; round < 16; ++round) {
        c = rotate_left_28(c, uint(SHIFTS[round]));
        d = rotate_left_28(d, uint(SHIFTS[round]));
        const ulong cd = (c << 28) | d;
        round_keys[round] = permute(cd << 8, PC2, 48, 64);
    }

    const ulong state = permute(block, IP, 64, 64);
    uint left = uint(state >> 32);
    uint right = uint(state & 0xfffffffful);

    for (uint round = 0; round < 16; ++round) {
        const uint next_left = right;
        const uint next_right = left ^ feistel(right, round_keys, round);
        left = next_left;
        right = next_right;
    }

    const ulong preoutput = (ulong(right) << 32) | ulong(left);
    return permute(preoutput, FP, 64, 64);
}

kernel void dst_kernel(const device uchar* keys [[buffer(0)]],
                       const device uchar* user [[buffer(1)]],
                       const device uchar* target [[buffer(2)]],
                       device uint* matches [[buffer(3)]],
                       constant uint& count [[buffer(4)]],
                       uint gid [[thread_position_in_grid]])
{
    if (gid >= count) {
        return;
    }

    const ulong key = load_be64(keys + (gid * 8));
    const ulong user_block = load_be64(user);
    const ulong target_block = load_be64(target);
    const ulong hash = des_encrypt(key, user_block);
    matches[gid] = hash == target_block ? 1u : 0u;
}
)metal";

struct MetalState {
    id<MTLDevice> device = nil;
    id<MTLCommandQueue> queue = nil;
    id<MTLComputePipelineState> pipeline = nil;
    std::string error;
    bool initialized = false;

    MetalState()
    {
        @autoreleasepool {
            device = MTLCreateSystemDefaultDevice();
            if (device == nil) {
                NSArray<id<MTLDevice>>* devices = MTLCopyAllDevices();
                if (devices != nil && [devices count] > 0) {
                    device = [devices objectAtIndex:0];
                }
            }
            if (device == nil) {
                error = "no Metal devices found";
                initialized = true;
                return;
            }

            NSError* ns_error = nil;
            NSString* source = [NSString stringWithUTF8String:kMetalKernelSource];
            if (source == nil) {
                error = "failed to create Metal source string";
                initialized = true;
                return;
            }

            id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&ns_error];
            if (library == nil) {
                error = ns_error ? std::string([[ns_error localizedDescription] UTF8String]) :
                                   "failed to compile Metal kernel";
                initialized = true;
                return;
            }

            id<MTLFunction> function = [library newFunctionWithName:@"dst_kernel"];
            if (function == nil) {
                error = "failed to create Metal kernel function";
                initialized = true;
                return;
            }

            pipeline = [device newComputePipelineStateWithFunction:function error:&ns_error];
            if (pipeline == nil) {
                error = ns_error ? std::string([[ns_error localizedDescription] UTF8String]) :
                                   "failed to create Metal compute pipeline";
                initialized = true;
                return;
            }

            queue = [device newCommandQueue];
            if (queue == nil) {
                error = "failed to create Metal command queue";
                initialized = true;
                return;
            }

            initialized = true;
        }
    }

    bool ready() const
    {
        return initialized && device != nil && queue != nil && pipeline != nil;
    }
};

MetalState& state()
{
    static MetalState s;
    return s;
}

std::string nsstring_to_string(NSString* value)
{
    if (value == nil) {
        return std::string();
    }
    const char* utf8 = [value UTF8String];
    if (utf8 == nil) {
        return std::string();
    }
    return std::string(utf8);
}

}  // namespace

bool compiled()
{
    return true;
}

bool available()
{
    return state().device != nil;
}

std::string device_description()
{
    const MetalState& s = state();
    if (s.device == nil) {
        return "Metal support compiled in, but no default device was created";
    }
    if (!s.ready()) {
        if (!s.error.empty()) {
            return std::string("Metal support compiled in, but initialization failed: ") + s.error;
        }
        return "Metal support compiled in, but initialization did not complete";
    }

    @autoreleasepool {
        std::ostringstream oss;
        oss << "Metal device: " << nsstring_to_string(s.device.name);
        oss << ", max threads per threadgroup: " << s.pipeline.maxTotalThreadsPerThreadgroup;
        oss << ", batch size: " << kBatchSize;
        return oss.str();
    }
}

std::size_t batch_size()
{
    return kBatchSize;
}

bool crack_batch(const std::vector<dst::Block8>& encoded_passwords,
                 const dst::Block8& user,
                 const dst::Block8& target,
                 std::size_t& match_index)
{
    MetalState& s = state();
    if (!s.ready()) {
        throw std::runtime_error(s.error.empty() ? "Metal backend is not available" : s.error);
    }
    if (encoded_passwords.empty()) {
        return false;
    }
    if (encoded_passwords.size() > static_cast<std::size_t>(std::numeric_limits<uint32_t>::max())) {
        throw std::runtime_error("Metal batch is too large");
    }

    @autoreleasepool {
        const std::size_t candidate_count = encoded_passwords.size();
        const std::size_t key_bytes = candidate_count * sizeof(dst::Block8);
        const std::size_t match_bytes = candidate_count * sizeof(std::uint32_t);

        id<MTLBuffer> key_buffer = [s.device newBufferWithBytes:encoded_passwords.data()
                                                         length:key_bytes
                                                        options:MTLResourceStorageModeShared];
        id<MTLBuffer> user_buffer = [s.device newBufferWithBytes:user.data()
                                                         length:user.size()
                                                        options:MTLResourceStorageModeShared];
        id<MTLBuffer> target_buffer = [s.device newBufferWithBytes:target.data()
                                                           length:target.size()
                                                          options:MTLResourceStorageModeShared];
        id<MTLBuffer> match_buffer = [s.device newBufferWithLength:match_bytes
                                                           options:MTLResourceStorageModeShared];

        if (key_buffer == nil || user_buffer == nil || target_buffer == nil || match_buffer == nil) {
            throw std::runtime_error("failed to allocate Metal buffers");
        }

        id<MTLCommandBuffer> command_buffer = [s.queue commandBuffer];
        if (command_buffer == nil) {
            throw std::runtime_error("failed to create Metal command buffer");
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            throw std::runtime_error("failed to create Metal command encoder");
        }

        [encoder setComputePipelineState:s.pipeline];
        [encoder setBuffer:key_buffer offset:0 atIndex:0];
        [encoder setBuffer:user_buffer offset:0 atIndex:1];
        [encoder setBuffer:target_buffer offset:0 atIndex:2];
        [encoder setBuffer:match_buffer offset:0 atIndex:3];

        const uint32_t count = static_cast<uint32_t>(candidate_count);
        [encoder setBytes:&count length:sizeof(count) atIndex:4];

        const NSUInteger width = std::min<NSUInteger>(s.pipeline.maxTotalThreadsPerThreadgroup,
                                                      static_cast<NSUInteger>(candidate_count));
        const NSUInteger tg_width = width == 0 ? 1 : width;
        const MTLSize grid_size = MTLSizeMake(candidate_count, 1, 1);
        const MTLSize tg_size = MTLSizeMake(tg_width, 1, 1);

        [encoder dispatchThreads:grid_size threadsPerThreadgroup:tg_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        const auto* matches = static_cast<const std::uint32_t*>([match_buffer contents]);
        for (std::size_t i = 0; i < candidate_count; ++i) {
            if (matches[i] != 0) {
                match_index = i;
                return true;
            }
        }
    }

    return false;
}

}  // namespace metal_backend
