#pragma once

#include "../dst_hash.hpp"

#include <cstddef>
#include <string>
#include <vector>

#if defined(IBMBRUTE_HAVE_METAL) && IBMBRUTE_HAVE_METAL
namespace metal_backend {

bool compiled();
bool available();
std::string device_description();
std::size_t batch_size();
bool crack_batch(const std::vector<dst::Block8>& encoded_passwords,
                 const dst::Block8& user,
                 const dst::Block8& target,
                 std::size_t& match_index);

}  // namespace metal_backend
#else
namespace metal_backend {

inline bool compiled() {
    return false;
}

inline std::string device_description() {
    return "Metal support not compiled in";
}

inline std::size_t batch_size() {
    return 0;
}

inline bool crack_batch(const std::vector<dst::Block8>&,
                        const dst::Block8&,
                        const dst::Block8&,
                        std::size_t&) {
    return false;
}

}  // namespace metal_backend
#endif
