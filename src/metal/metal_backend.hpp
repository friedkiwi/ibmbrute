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
std::vector<std::size_t> crack_batch_matches(const std::vector<dst::Block8>& encoded_passwords,
                                             const dst::Block8& user,
                                             const dst::Block8& target);

}  // namespace metal_backend
#else
namespace metal_backend {

inline bool compiled() {
    return false;
}

// Required by callers that ask "is the Metal engine usable right now?"  The
// real (Apple) implementation answers from the live device list.  The stub
// always reports false so resolve_engine() falls back to the multithreaded
// CPU path on non-Apple hosts.  Without this stub the program failed to
// link on Linux and Windows.
inline bool available() {
    return false;
}

inline std::string device_description() {
    return "Metal support not compiled in";
}

inline std::size_t batch_size() {
    return 0;
}

inline std::vector<std::size_t> crack_batch_matches(const std::vector<dst::Block8>&,
                                                    const dst::Block8&,
                                                    const dst::Block8&) {
    return {};
}

}  // namespace metal_backend
#endif
