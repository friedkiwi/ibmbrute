#include "cuda_backend.hpp"

#include <cuda_runtime.h>

#include <cstdint>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace cuda_backend {

namespace {

constexpr std::size_t kBatchSize = 65536;
constexpr unsigned int kThreadsPerBlock = 256;

__constant__ unsigned char kIP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
};

__constant__ unsigned char kFP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
};

__constant__ unsigned char kE[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
};

__constant__ unsigned char kP[32] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
};

__constant__ unsigned char kPC1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
};

__constant__ unsigned char kPC2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
};

__constant__ unsigned char kShifts[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

__constant__ unsigned char kSbox[8][64] = {
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

template <typename T>
struct DeviceBuffer {
    T* ptr = nullptr;

    ~DeviceBuffer()
    {
        if (ptr != nullptr) {
            cudaFree(ptr);
        }
    }
};

struct CudaState {
    DeviceBuffer<unsigned char> passwords;
    DeviceBuffer<unsigned char> user_key;
    DeviceBuffer<unsigned char> target;
    DeviceBuffer<unsigned int> matches;
    std::size_t password_capacity = 0;
    std::size_t match_capacity = 0;
    bool scalar_buffers_ready = false;
};

CudaState& state()
{
    static CudaState s;
    return s;
}

void check_cuda(cudaError_t status, const char* action)
{
    if (status != cudaSuccess) {
        std::ostringstream oss;
        oss << action << ": " << cudaGetErrorString(status);
        throw std::runtime_error(oss.str());
    }
}

bool probe_device(cudaDeviceProp* prop, std::string* error)
{
    int device_count = 0;
    const cudaError_t count_status = cudaGetDeviceCount(&device_count);
    if (count_status != cudaSuccess) {
        if (error != nullptr) {
            *error = cudaGetErrorString(count_status);
        }
        return false;
    }
    if (device_count <= 0) {
        if (error != nullptr) {
            *error = "no CUDA devices found";
        }
        return false;
    }

    cudaDeviceProp local_prop{};
    const cudaError_t prop_status = cudaGetDeviceProperties(&local_prop, 0);
    if (prop_status != cudaSuccess) {
        if (error != nullptr) {
            *error = cudaGetErrorString(prop_status);
        }
        return false;
    }

    if (prop != nullptr) {
        *prop = local_prop;
    }
    return true;
}

template <typename T>
void ensure_capacity(DeviceBuffer<T>& buffer, std::size_t& capacity, std::size_t required, const char* action)
{
    if (capacity >= required && buffer.ptr != nullptr) {
        return;
    }
    if (buffer.ptr != nullptr) {
        check_cuda(cudaFree(buffer.ptr), "failed to release CUDA buffer");
        buffer.ptr = nullptr;
        capacity = 0;
    }
    check_cuda(cudaMalloc(&buffer.ptr, required), action);
    capacity = required;
}

void ensure_buffers(std::size_t password_bytes, std::size_t match_bytes)
{
    CudaState& s = state();
    ensure_capacity(s.passwords, s.password_capacity, password_bytes, "failed to allocate CUDA password buffer");
    ensure_capacity(s.matches, s.match_capacity, match_bytes, "failed to allocate CUDA match buffer");
    if (!s.scalar_buffers_ready) {
        check_cuda(cudaMalloc(&s.user_key.ptr, sizeof(dst::Block8)), "failed to allocate CUDA user buffer");
        check_cuda(cudaMalloc(&s.target.ptr, sizeof(dst::Block8)), "failed to allocate CUDA target buffer");
        s.scalar_buffers_ready = true;
    }
}

__device__ __forceinline__ unsigned long long permute(unsigned long long input,
                                                      const unsigned char* table,
                                                      unsigned int count,
                                                      unsigned int input_bits)
{
    unsigned long long output = 0;
    for (unsigned int i = 0; i < count; ++i) {
        output <<= 1;
        const unsigned int bit_index = input_bits - static_cast<unsigned int>(table[i]);
        output |= (input >> bit_index) & 1ull;
    }
    return output;
}

__device__ __forceinline__ unsigned long long load_be64(const unsigned char* bytes)
{
    unsigned long long value = 0;
    for (unsigned int i = 0; i < 8; ++i) {
        value = (value << 8) | static_cast<unsigned long long>(bytes[i]);
    }
    return value;
}

__device__ __forceinline__ unsigned long long rotate_left_28(unsigned long long value, unsigned int shift)
{
    value &= 0x0fffffffull;
    return ((value << shift) | (value >> (28 - shift))) & 0x0fffffffull;
}

__device__ __forceinline__ unsigned int feistel(unsigned int value,
                                                const unsigned long long* round_keys,
                                                unsigned int round)
{
    const unsigned long long expanded = permute(static_cast<unsigned long long>(value) << 32, kE, 48, 64);
    const unsigned long long mixed = expanded ^ round_keys[round];

    unsigned int substituted = 0;
    for (unsigned int box = 0; box < 8; ++box) {
        const unsigned int shift = 42 - (box * 6);
        const unsigned char chunk = static_cast<unsigned char>((mixed >> shift) & 0x3full);
        const unsigned char row = static_cast<unsigned char>(((chunk & 0x20u) >> 4) | (chunk & 0x01u));
        const unsigned char col = static_cast<unsigned char>((chunk >> 1) & 0x0fu);
        const unsigned char svalue = kSbox[box][row * 16 + col];
        substituted = (substituted << 4) | static_cast<unsigned int>(svalue);
    }

    return static_cast<unsigned int>(permute(static_cast<unsigned long long>(substituted) << 32, kP, 32, 64));
}

__device__ __forceinline__ unsigned long long des_encrypt(unsigned long long key, unsigned long long block)
{
    unsigned long long round_keys[16];

    const unsigned long long pc1 = permute(key, kPC1, 56, 64);
    unsigned long long c = (pc1 >> 28) & 0x0fffffffull;
    unsigned long long d = pc1 & 0x0fffffffull;

    for (unsigned int round = 0; round < 16; ++round) {
        c = rotate_left_28(c, static_cast<unsigned int>(kShifts[round]));
        d = rotate_left_28(d, static_cast<unsigned int>(kShifts[round]));
        const unsigned long long cd = (c << 28) | d;
        round_keys[round] = permute(cd << 8, kPC2, 48, 64);
    }

    const unsigned long long state = permute(block, kIP, 64, 64);
    unsigned int left = static_cast<unsigned int>(state >> 32);
    unsigned int right = static_cast<unsigned int>(state & 0xffffffffull);

    for (unsigned int round = 0; round < 16; ++round) {
        const unsigned int next_left = right;
        const unsigned int next_right = left ^ feistel(right, round_keys, round);
        left = next_left;
        right = next_right;
    }

    const unsigned long long preoutput =
        (static_cast<unsigned long long>(right) << 32) | static_cast<unsigned long long>(left);
    return permute(preoutput, kFP, 64, 64);
}

__global__ void dst_kernel(const unsigned char* passwords,
                           const unsigned char* user_key,
                           const unsigned char* target,
                           unsigned int* matches,
                           unsigned int count)
{
    const unsigned int gid = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (gid >= count) {
        return;
    }

    const unsigned long long key = load_be64(user_key);
    const unsigned long long password_block = load_be64(passwords + (gid * 8u));
    const unsigned long long target_block = load_be64(target);
    const unsigned long long hash = des_encrypt(key, password_block);
    matches[gid] = (hash == target_block) ? 1u : 0u;
}

}  // namespace

bool compiled()
{
    return true;
}

bool available()
{
    return probe_device(nullptr, nullptr);
}

std::string device_description()
{
    cudaDeviceProp prop{};
    std::string error;
    if (!probe_device(&prop, &error)) {
        return std::string("CUDA support compiled in, but runtime initialization failed: ") + error;
    }

    std::ostringstream oss;
    oss << "CUDA device: " << prop.name
        << ", compute capability " << prop.major << '.' << prop.minor
        << ", global memory " << (prop.totalGlobalMem / (1024ull * 1024ull)) << " MiB"
        << ", batch size: " << kBatchSize;
    return oss.str();
}

std::size_t batch_size()
{
    return kBatchSize;
}

std::vector<std::size_t> crack_batch_matches(const std::vector<dst::Block8>& encoded_passwords,
                                             const dst::Block8& user_key,
                                             const dst::Block8& target)
{
    if (encoded_passwords.empty()) {
        return {};
    }
    if (encoded_passwords.size() > static_cast<std::size_t>(std::numeric_limits<unsigned int>::max())) {
        throw std::runtime_error("CUDA batch is too large");
    }

    check_cuda(cudaSetDevice(0), "failed to select CUDA device");

    const std::size_t candidate_count = encoded_passwords.size();
    const std::size_t key_bytes = candidate_count * sizeof(dst::Block8);
    const std::size_t match_bytes = candidate_count * sizeof(unsigned int);

    CudaState& s = state();
    ensure_buffers(key_bytes, match_bytes);

    check_cuda(cudaMemcpy(s.passwords.ptr,
                          encoded_passwords.data(),
                          key_bytes,
                          cudaMemcpyHostToDevice),
               "failed to upload CUDA password buffer");
    check_cuda(cudaMemcpy(s.user_key.ptr,
                          user_key.data(),
                          user_key.size(),
                          cudaMemcpyHostToDevice),
               "failed to upload CUDA user buffer");
    check_cuda(cudaMemcpy(s.target.ptr,
                          target.data(),
                          target.size(),
                          cudaMemcpyHostToDevice),
               "failed to upload CUDA target buffer");

    const unsigned int count = static_cast<unsigned int>(candidate_count);
    const unsigned int block_count = (count + kThreadsPerBlock - 1) / kThreadsPerBlock;
    dst_kernel<<<block_count, kThreadsPerBlock>>>(s.passwords.ptr,
                                                  s.user_key.ptr,
                                                  s.target.ptr,
                                                  s.matches.ptr,
                                                  count);
    check_cuda(cudaGetLastError(), "failed to launch CUDA kernel");
    check_cuda(cudaDeviceSynchronize(), "failed to execute CUDA kernel");

    std::vector<unsigned int> matches(candidate_count, 0);
    check_cuda(cudaMemcpy(matches.data(),
                          s.matches.ptr,
                          match_bytes,
                          cudaMemcpyDeviceToHost),
               "failed to download CUDA match buffer");

    std::vector<std::size_t> match_indices;
    for (std::size_t i = 0; i < candidate_count; ++i) {
        if (matches[i] != 0) {
            match_indices.push_back(i);
        }
    }
    return match_indices;
}

}  // namespace cuda_backend
