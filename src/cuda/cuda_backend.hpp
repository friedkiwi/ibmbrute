#pragma once

#include "../dst_hash.hpp"

#include <cstddef>
#include <string>
#include <vector>

#if defined(IBMBRUTE_HAVE_CUDA) && IBMBRUTE_HAVE_CUDA
namespace cuda_backend {

bool compiled();
bool available();
std::string device_description();
std::size_t batch_size();
std::vector<std::size_t> crack_batch_matches(const std::vector<dst::Block8>& encoded_passwords,
                                             const dst::Block8& user_key,
                                             const dst::Block8& target);

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

inline std::vector<std::size_t> crack_batch_matches(const std::vector<dst::Block8>&,
                                                    const dst::Block8&,
                                                    const dst::Block8&) {
    return {};
}

}  // namespace cuda_backend
#endif
