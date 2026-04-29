#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include "metal_backend.hpp"

namespace metal_backend {

bool compiled() {
    return true;
}

std::string device_description() {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (device == nil) {
            return "Metal support compiled in, but no default device was created";
        }

        NSString* name = device.name;
        if (name == nil) {
            return "Metal support compiled in, default device name unavailable";
        }

        return std::string("Metal support compiled in, default device: ") + [name UTF8String];
    }
}

}  // namespace metal_backend
