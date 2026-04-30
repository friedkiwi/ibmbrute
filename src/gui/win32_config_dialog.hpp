#pragma once

#include <cstddef>

#include <windows.h>

namespace ibmbrute_gui {

struct LaunchConfig {
    std::size_t cuda_batch_size = 0;
    unsigned int cuda_thread_count = 0;
};

bool show_config_dialog(HWND owner, LaunchConfig& config);

}  // namespace ibmbrute_gui
