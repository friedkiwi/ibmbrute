#pragma once

#include <string>

#if defined(IBMBRUTE_HAVE_METAL) && IBMBRUTE_HAVE_METAL
namespace metal_backend {

bool compiled();
std::string device_description();

}  // namespace metal_backend
#else
namespace metal_backend {

inline bool compiled() {
    return false;
}

inline std::string device_description() {
    return "Metal support not compiled in";
}

}  // namespace metal_backend
#endif
