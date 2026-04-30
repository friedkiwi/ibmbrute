#pragma once

#include "../dst_hash.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#if defined(IBMBRUTE_HAVE_CUDA) && IBMBRUTE_HAVE_CUDA
namespace cuda_backend {

struct PlanPattern {
    std::uint64_t start = 0;
    std::uint32_t length = 0;
    std::uint32_t offset_index = 0;
};

struct PlanData {
    std::vector<PlanPattern> patterns;
    std::vector<std::uint32_t> charset_offsets;
    std::vector<std::uint32_t> radices;
    std::vector<std::uint8_t> charset_bytes;
};

bool compiled();
bool available();
std::string device_description();
std::size_t batch_size();
void prepare_target(const PlanData& plan, const dst::Block8& user_key, const dst::Block8& target);
std::vector<std::size_t> crack_batch_matches(std::uint64_t batch_start,
                                             std::size_t candidate_count,
                                             bool keep_going);

}  // namespace cuda_backend
#else
namespace cuda_backend {

inline bool compiled() {
    return false;
}

inline bool available() {
    return false;
}

inline std::string device_description() {
    return "CUDA support not compiled in";
}

inline std::size_t batch_size() {
    return 0;
}

struct PlanPattern {
    std::uint64_t start = 0;
    std::uint32_t length = 0;
    std::uint32_t offset_index = 0;
};

struct PlanData {
    std::vector<PlanPattern> patterns;
    std::vector<std::uint32_t> charset_offsets;
    std::vector<std::uint32_t> radices;
    std::vector<std::uint8_t> charset_bytes;
};

inline void prepare_target(const PlanData&, const dst::Block8&, const dst::Block8&) {
}

inline std::vector<std::size_t> crack_batch_matches(std::uint64_t,
                                                    std::size_t,
                                                    bool) {
    return {};
}

}  // namespace cuda_backend
#endif
