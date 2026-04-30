#include "cuda_backend.hpp"

#include <cuda_runtime.h>

#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace cuda_backend {

namespace {

const std::vector<unsigned int>& thread_candidates()
{
    static const std::vector<unsigned int> values = {128, 192, 256, 320, 384, 448, 512, 576,
                                                     640, 704, 768, 832, 896, 960, 1024};
    return values;
}

const std::vector<std::size_t>& batch_candidates()
{
    static const std::vector<std::size_t> values =
        {8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608, 262144, 393216,
         524288, 786432, 1048576, 1572864, 2097152, 3145728, 4194304, 6291456, 8388608, 12582912, 16777216,
         33554432, 67108864};
    return values;
}

constexpr std::size_t kDefaultBatchSize = 65536;
constexpr unsigned int kDefaultThreadsPerBlock = 256;

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

template <typename T>
void free_device_buffer(DeviceBuffer<T>& buffer)
{
    if (buffer.ptr != nullptr) {
        cudaFree(buffer.ptr);
        buffer.ptr = nullptr;
    }
}

struct CudaState {
    DeviceBuffer<unsigned char> user_key;
    DeviceBuffer<unsigned char> target;
    DeviceBuffer<unsigned int> matches;
    DeviceBuffer<unsigned int> found_index;
    DeviceBuffer<unsigned long long> round_keys;
    DeviceBuffer<PlanPattern> patterns;
    DeviceBuffer<unsigned int> charset_offsets;
    DeviceBuffer<unsigned int> radices;
    DeviceBuffer<unsigned char> charset_bytes;
    std::size_t match_capacity = 0;
    std::size_t pattern_capacity = 0;
    std::size_t charset_offset_capacity = 0;
    std::size_t radix_capacity = 0;
    std::size_t charset_byte_capacity = 0;
    std::size_t pattern_count = 0;
    std::size_t charset_offset_count = 0;
    std::size_t radix_count = 0;
    std::size_t charset_byte_count = 0;
    std::size_t configured_batch_size = kDefaultBatchSize;
    unsigned int configured_thread_count = kDefaultThreadsPerBlock;
    int selected_device_index = 0;
    bool scalar_buffers_ready = false;
    bool target_prepared = false;
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
        oss << action << ": " << cudaGetErrorName(status)
            << " (" << static_cast<int>(status) << "): " << cudaGetErrorString(status);
        throw std::runtime_error(oss.str());
    }
}

std::string cuda_error_text(cudaError_t status)
{
    std::ostringstream oss;
    oss << cudaGetErrorName(status) << " (" << static_cast<int>(status)
        << "): " << cudaGetErrorString(status);
    return oss.str();
}

std::string runtime_versions()
{
    int driver_version = 0;
    int runtime_version = 0;
    const cudaError_t driver_status = cudaDriverGetVersion(&driver_version);
    const cudaError_t runtime_status = cudaRuntimeGetVersion(&runtime_version);

    std::ostringstream oss;
    oss << "driver version ";
    if (driver_status == cudaSuccess && driver_version != 0) {
        oss << driver_version;
    } else if (driver_status == cudaSuccess) {
        oss << "not loaded";
    } else {
        oss << cuda_error_text(driver_status);
    }

    oss << ", runtime version ";
    if (runtime_status == cudaSuccess) {
        oss << runtime_version;
    } else {
        oss << cuda_error_text(runtime_status);
    }
    return oss.str();
}

std::string format_rate(double value)
{
    const char* suffix = "";
    if (value >= 1e9) {
        value /= 1e9;
        suffix = "g";
    } else if (value >= 1e6) {
        value /= 1e6;
        suffix = "m";
    } else if (value >= 1e3) {
        value /= 1e3;
        suffix = "k";
    }

    std::ostringstream oss;
    oss.setf(std::ios::fixed, std::ios::floatfield);
    oss.precision(3);
    oss << value << suffix;
    return oss.str();
}

bool probe_device(int index, cudaDeviceProp* prop, std::string* error)
{
    int device_count = 0;
    const cudaError_t count_status = cudaGetDeviceCount(&device_count);
    if (count_status != cudaSuccess) {
        if (error != nullptr) {
            *error = cuda_error_text(count_status) + " (" + runtime_versions() + ")";
        }
        return false;
    }
    if (device_count <= 0) {
        if (error != nullptr) {
            *error = "no CUDA devices found";
        }
        return false;
    }
    if (index < 0 || index >= device_count) {
        if (error != nullptr) {
            *error = "selected CUDA device index is out of range";
        }
        return false;
    }

    cudaDeviceProp local_prop{};
    const cudaError_t prop_status = cudaGetDeviceProperties(&local_prop, index);
    if (prop_status != cudaSuccess) {
        if (error != nullptr) {
            *error = cuda_error_text(prop_status) + " (" + runtime_versions() + ")";
        }
        return false;
    }

    if (prop != nullptr) {
        *prop = local_prop;
    }
    return true;
}

void reset_state_buffers()
{
    CudaState& s = state();

    free_device_buffer(s.user_key);
    free_device_buffer(s.target);
    free_device_buffer(s.matches);
    free_device_buffer(s.found_index);
    free_device_buffer(s.round_keys);
    free_device_buffer(s.patterns);
    free_device_buffer(s.charset_offsets);
    free_device_buffer(s.radices);
    free_device_buffer(s.charset_bytes);

    s.match_capacity = 0;
    s.pattern_capacity = 0;
    s.charset_offset_capacity = 0;
    s.radix_capacity = 0;
    s.charset_byte_capacity = 0;
    s.pattern_count = 0;
    s.charset_offset_count = 0;
    s.radix_count = 0;
    s.charset_byte_count = 0;
    s.scalar_buffers_ready = false;
    s.target_prepared = false;
}

template <typename T>
void ensure_capacity(DeviceBuffer<T>& buffer, std::size_t& capacity, std::size_t required, const char* action)
{
    if (required == 0) {
        return;
    }
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

void ensure_buffers(std::size_t, std::size_t match_bytes)
{
    CudaState& s = state();
    ensure_capacity(s.matches, s.match_capacity, match_bytes, "failed to allocate CUDA match buffer");
    if (!s.scalar_buffers_ready) {
        check_cuda(cudaMalloc(&s.user_key.ptr, sizeof(dst::Block8)), "failed to allocate CUDA user buffer");
        check_cuda(cudaMalloc(&s.target.ptr, sizeof(dst::Block8)), "failed to allocate CUDA target buffer");
        check_cuda(cudaMalloc(&s.round_keys.ptr, 16 * sizeof(unsigned long long)),
                   "failed to allocate CUDA round-key buffer");
        check_cuda(cudaMalloc(&s.found_index.ptr, sizeof(unsigned int)),
                   "failed to allocate CUDA found-index buffer");
        s.scalar_buffers_ready = true;
    }
}

void ensure_plan_buffers(const PlanData& plan)
{
    CudaState& s = state();
    ensure_capacity(s.patterns,
                    s.pattern_capacity,
                    plan.patterns.size() * sizeof(PlanPattern),
                    "failed to allocate CUDA pattern buffer");
    ensure_capacity(s.charset_offsets,
                    s.charset_offset_capacity,
                    plan.charset_offsets.size() * sizeof(unsigned int),
                    "failed to allocate CUDA charset-offset buffer");
    ensure_capacity(s.radices,
                    s.radix_capacity,
                    plan.radices.size() * sizeof(unsigned int),
                    "failed to allocate CUDA radix buffer");
    ensure_capacity(s.charset_bytes,
                    s.charset_byte_capacity,
                    plan.charset_bytes.size() * sizeof(unsigned char),
                    "failed to allocate CUDA charset buffer");
    s.pattern_count = plan.patterns.size();
    s.charset_offset_count = plan.charset_offsets.size();
    s.radix_count = plan.radices.size();
    s.charset_byte_count = plan.charset_bytes.size();
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

__device__ __forceinline__ void build_round_keys(unsigned long long key, unsigned long long* round_keys)
{
    const unsigned long long pc1 = permute(key, kPC1, 56, 64);
    unsigned long long c = (pc1 >> 28) & 0x0fffffffull;
    unsigned long long d = pc1 & 0x0fffffffull;

    for (unsigned int round = 0; round < 16; ++round) {
        c = rotate_left_28(c, static_cast<unsigned int>(kShifts[round]));
        d = rotate_left_28(d, static_cast<unsigned int>(kShifts[round]));
        const unsigned long long cd = (c << 28) | d;
        round_keys[round] = permute(cd << 8, kPC2, 48, 64);
    }
}

__device__ __forceinline__ unsigned long long des_encrypt_with_round_keys(const unsigned long long* round_keys,
                                                                          unsigned long long block)
{
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

__device__ __forceinline__ unsigned long long build_candidate_block(const PlanPattern* patterns,
                                                                    unsigned int pattern_count,
                                                                    const unsigned int* charset_offsets,
                                                                    const unsigned int* radices,
                                                                    const unsigned char* charset_bytes,
                                                                    unsigned long long global_index)
{
    unsigned char password_bytes[8];
    for (unsigned int i = 0; i < 8; ++i) {
        password_bytes[i] = 0x40u;
    }

    PlanPattern pattern = patterns[0];
    for (unsigned int i = 0; i < pattern_count; ++i) {
        const unsigned long long pattern_start = patterns[i].start;
        const unsigned long long next_start = (i + 1u < pattern_count) ? patterns[i + 1u].start
                                                                        : 0xffffffffffffffffull;
        if (global_index >= pattern_start && global_index < next_start) {
            pattern = patterns[i];
            global_index -= pattern_start;
            break;
        }
    }

    for (int pos = static_cast<int>(pattern.length) - 1; pos >= 0; --pos) {
        const unsigned int plan_index = pattern.offset_index + static_cast<unsigned int>(pos);
        const unsigned int radix = radices[plan_index];
        const unsigned int digit = static_cast<unsigned int>(global_index % radix);
        global_index /= radix;
        if (pos < 8) {
            password_bytes[pos] = charset_bytes[charset_offsets[plan_index] + digit];
        }
    }

    return load_be64(password_bytes);
}

__global__ void init_round_keys_kernel(const unsigned char* user_key, unsigned long long* round_keys)
{
    if (blockIdx.x == 0 && threadIdx.x == 0) {
        build_round_keys(load_be64(user_key), round_keys);
    }
}

__global__ void dst_kernel(const PlanPattern* patterns,
                           unsigned int pattern_count,
                           const unsigned int* charset_offsets,
                           const unsigned int* radices,
                           const unsigned char* charset_bytes,
                           const unsigned long long* round_keys,
                           const unsigned char* target,
                           unsigned int* matches,
                           unsigned int* found_index,
                           unsigned long long batch_start,
                           unsigned int collect_all,
                           unsigned int count)
{
    const unsigned int gid = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (gid >= count) {
        return;
    }
    if (collect_all == 0u && *found_index != 0xffffffffu) {
        return;
    }

    const unsigned long long password_block =
        build_candidate_block(patterns, pattern_count, charset_offsets, radices, charset_bytes, batch_start + gid);
    const unsigned long long target_block = load_be64(target);
    const unsigned long long hash = des_encrypt_with_round_keys(round_keys, password_block);

    if (hash != target_block) {
        if (collect_all != 0u) {
            matches[gid] = 0u;
        }
        return;
    }

    if (collect_all != 0u) {
        matches[gid] = 1u;
    } else {
        atomicMin(found_index, gid);
    }
}

}  // namespace

bool compiled()
{
    return true;
}

bool available()
{
    return probe_device(state().selected_device_index, nullptr, nullptr);
}

std::vector<DeviceInfo> devices()
{
    std::vector<DeviceInfo> out;
    int device_count = 0;
    if (cudaGetDeviceCount(&device_count) != cudaSuccess || device_count <= 0) {
        return out;
    }

    out.reserve(static_cast<std::size_t>(device_count));
    for (int index = 0; index < device_count; ++index) {
        cudaDeviceProp prop{};
        if (cudaGetDeviceProperties(&prop, index) != cudaSuccess) {
            continue;
        }

        DeviceInfo info;
        info.index = index;
        info.name = prop.name;
        info.major = prop.major;
        info.minor = prop.minor;
        info.total_global_mem = static_cast<std::size_t>(prop.totalGlobalMem);
        out.push_back(std::move(info));
    }
    return out;
}

std::vector<unsigned int> benchmark_thread_candidates()
{
    return thread_candidates();
}

std::vector<std::size_t> benchmark_batch_candidates()
{
    return batch_candidates();
}

int selected_device()
{
    return state().selected_device_index;
}

void select_device(int index)
{
    CudaState& s = state();
    if (index == s.selected_device_index) {
        return;
    }

    if (s.scalar_buffers_ready || s.target_prepared || s.matches.ptr != nullptr || s.patterns.ptr != nullptr) {
        check_cuda(cudaSetDevice(s.selected_device_index), "failed to reselect previous CUDA device");
        reset_state_buffers();
    }

    cudaDeviceProp prop{};
    std::string error;
    if (!probe_device(index, &prop, &error)) {
        throw std::runtime_error(std::string("failed to select CUDA device: ") + error);
    }
    check_cuda(cudaSetDevice(index), "failed to select CUDA device");
    s.selected_device_index = index;
}

std::string device_description()
{
    cudaDeviceProp prop{};
    std::string error;
    if (!probe_device(state().selected_device_index, &prop, &error)) {
        return std::string("CUDA support compiled in, but runtime initialization failed: ") + error;
    }

    std::ostringstream oss;
    oss << "CUDA device: " << prop.name
        << ", compute capability " << prop.major << '.' << prop.minor
        << ", global memory " << (prop.totalGlobalMem / (1024ull * 1024ull)) << " MiB"
        << ", batch size: " << state().configured_batch_size
        << ", threads per block: " << state().configured_thread_count;
    return oss.str();
}

std::size_t batch_size()
{
    return state().configured_batch_size;
}

unsigned int thread_count()
{
    return state().configured_thread_count;
}

void set_launch_config(std::size_t batch, unsigned int threads)
{
    if (batch == 0) {
        throw std::runtime_error("CUDA batch size must be greater than zero");
    }
    if (threads == 0) {
        throw std::runtime_error("CUDA thread count must be greater than zero");
    }
    if (threads > 1024) {
        throw std::runtime_error("CUDA thread count must be at most 1024");
    }
    if ((threads % 32u) != 0u) {
        throw std::runtime_error("CUDA thread count must be a multiple of 32");
    }

    CudaState& s = state();
    s.configured_batch_size = batch;
    s.configured_thread_count = threads;
}

void prepare_target(const PlanData& plan, const dst::Block8& user_key, const dst::Block8& target)
{
    check_cuda(cudaSetDevice(state().selected_device_index), "failed to select CUDA device");
    ensure_buffers(0, 0);
    ensure_plan_buffers(plan);

    CudaState& s = state();
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
    check_cuda(cudaMemcpy(s.patterns.ptr,
                          plan.patterns.data(),
                          plan.patterns.size() * sizeof(PlanPattern),
                          cudaMemcpyHostToDevice),
               "failed to upload CUDA pattern buffer");
    check_cuda(cudaMemcpy(s.charset_offsets.ptr,
                          plan.charset_offsets.data(),
                          plan.charset_offsets.size() * sizeof(unsigned int),
                          cudaMemcpyHostToDevice),
               "failed to upload CUDA charset-offset buffer");
    check_cuda(cudaMemcpy(s.radices.ptr,
                          plan.radices.data(),
                          plan.radices.size() * sizeof(unsigned int),
                          cudaMemcpyHostToDevice),
               "failed to upload CUDA radix buffer");
    check_cuda(cudaMemcpy(s.charset_bytes.ptr,
                          plan.charset_bytes.data(),
                          plan.charset_bytes.size() * sizeof(unsigned char),
                          cudaMemcpyHostToDevice),
               "failed to upload CUDA charset buffer");

    init_round_keys_kernel<<<1, 1>>>(s.user_key.ptr, s.round_keys.ptr);
    check_cuda(cudaGetLastError(), "failed to launch CUDA round-key kernel");
    check_cuda(cudaDeviceSynchronize(), "failed to build CUDA round keys");
    s.target_prepared = true;
}

std::vector<std::size_t> crack_batch_matches(std::uint64_t batch_start,
                                             std::size_t candidate_count,
                                             bool keep_going)
{
    if (candidate_count == 0) {
        return {};
    }
    if (candidate_count > static_cast<std::size_t>(std::numeric_limits<unsigned int>::max())) {
        throw std::runtime_error("CUDA batch is too large");
    }

    check_cuda(cudaSetDevice(state().selected_device_index), "failed to select CUDA device");

    CudaState& s = state();
    if (!s.target_prepared) {
        throw std::runtime_error("CUDA target was not prepared before cracking");
    }

    const std::size_t match_bytes = candidate_count * sizeof(unsigned int);
    if (keep_going) {
        ensure_buffers(0, match_bytes);
    } else {
        ensure_buffers(0, 0);
        const unsigned int not_found = 0xffffffffu;
        check_cuda(cudaMemcpy(s.found_index.ptr,
                              &not_found,
                              sizeof(not_found),
                              cudaMemcpyHostToDevice),
                   "failed to reset CUDA found-index buffer");
    }

    const unsigned int count = static_cast<unsigned int>(candidate_count);
    const unsigned int threads_per_block = s.configured_thread_count;
    const unsigned int block_count = (count + threads_per_block - 1) / threads_per_block;
    dst_kernel<<<block_count, threads_per_block>>>(s.patterns.ptr,
                                                   static_cast<unsigned int>(s.pattern_count),
                                                   s.charset_offsets.ptr,
                                                   s.radices.ptr,
                                                   s.charset_bytes.ptr,
                                                   s.round_keys.ptr,
                                                   s.target.ptr,
                                                   s.matches.ptr,
                                                   s.found_index.ptr,
                                                   batch_start,
                                                   keep_going ? 1u : 0u,
                                                   count);
    check_cuda(cudaGetLastError(), "failed to launch CUDA kernel");
    check_cuda(cudaDeviceSynchronize(), "failed to execute CUDA kernel");

    std::vector<std::size_t> match_indices;
    if (keep_going) {
        std::vector<unsigned int> matches(candidate_count, 0);
        check_cuda(cudaMemcpy(matches.data(),
                              s.matches.ptr,
                              match_bytes,
                              cudaMemcpyDeviceToHost),
                   "failed to download CUDA match buffer");

        for (std::size_t i = 0; i < candidate_count; ++i) {
            if (matches[i] != 0) {
                match_indices.push_back(i);
            }
        }
    } else {
        unsigned int found_index = 0xffffffffu;
        check_cuda(cudaMemcpy(&found_index,
                              s.found_index.ptr,
                              sizeof(found_index),
                              cudaMemcpyDeviceToHost),
                   "failed to download CUDA found-index buffer");
        if (found_index != 0xffffffffu) {
            match_indices.push_back(found_index);
        }
    }
    return match_indices;
}

BenchmarkResult benchmark_with_progress(BenchmarkProgressCallback progress_callback, void* progress_context)
{
    if (!available()) {
        throw std::runtime_error("CUDA benchmark requested but CUDA is not available at runtime");
    }

    PlanData plan;
    PlanPattern pattern;
    pattern.start = 0;
    pattern.length = 8;
    pattern.offset_index = 0;
    plan.patterns.push_back(pattern);
    static constexpr const char* full_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#@$_";
    for (unsigned int i = 0; i < 8; ++i) {
        plan.charset_offsets.push_back(static_cast<unsigned int>(plan.charset_bytes.size()));
        plan.radices.push_back(40);
        for (const char* p = full_charset; *p != '\0'; ++p) {
            plan.charset_bytes.push_back(dst::ebcdic8(std::string(1, *p))[0]);
        }
    }

    const dst::Block8 user_key = dst::ebcdic8("QSECOFR");
    const dst::Block8 target{};
    prepare_target(plan, user_key, target);

    BenchmarkResult best;
    const std::size_t original_batch = batch_size();
    const unsigned int original_threads = thread_count();
    constexpr double kMinBenchmarkSeconds = 0.25;
    constexpr int kMinIterations = 8;
    const std::size_t total_candidates_to_test = thread_candidates().size() * batch_candidates().size();
    std::size_t completed = 0;

    for (unsigned int threads : thread_candidates()) {
        for (std::size_t batch : batch_candidates()) {
            if (progress_callback != nullptr) {
                BenchmarkProgress progress;
                progress.completed = completed;
                progress.total = total_candidates_to_test;
                progress.current_batch_size = batch;
                progress.current_thread_count = threads;
                progress.best_batch_size = best.batch_size;
                progress.best_thread_count = best.thread_count;
                progress.best_candidates_per_second = best.candidates_per_second;
                if (!progress_callback(progress, progress_context)) {
                    set_launch_config(original_batch, original_threads);
                    return best;
                }
            }

            std::cout << "benchmark: trying --cuda-thread-count " << threads
                      << " --cuda-batch-size " << batch << " ... " << std::flush;
            try {
                set_launch_config(batch, threads);
                crack_batch_matches(0, batch, false);

                const auto started = std::chrono::steady_clock::now();
                int iterations = 0;
                do {
                    crack_batch_matches(static_cast<std::uint64_t>(iterations) * batch, batch, false);
                    ++iterations;
                } while (iterations < kMinIterations ||
                         std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count() <
                             kMinBenchmarkSeconds);

                const double elapsed =
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
                const double cps = (static_cast<double>(batch) * iterations) / (elapsed > 1e-6 ? elapsed : 1e-6);

                std::cout << format_rate(cps) << " c/s over " << iterations
                          << " iterations in " << elapsed << "s" << '\n';

                if (cps > best.candidates_per_second) {
                    best.batch_size = batch;
                    best.thread_count = threads;
                    best.candidates_per_second = cps;
                }
            } catch (const std::exception& ex) {
                std::cout << "skipped (" << ex.what() << ')' << '\n';
            }
            ++completed;
        }
    }

    if (progress_callback != nullptr) {
        BenchmarkProgress progress;
        progress.completed = completed;
        progress.total = total_candidates_to_test;
        progress.best_batch_size = best.batch_size;
        progress.best_thread_count = best.thread_count;
        progress.best_candidates_per_second = best.candidates_per_second;
        static_cast<void>(progress_callback(progress, progress_context));
    }

    set_launch_config(original_batch, original_threads);
    return best;
}

BenchmarkResult benchmark()
{
    return benchmark_with_progress(nullptr, nullptr);
}

}  // namespace cuda_backend
