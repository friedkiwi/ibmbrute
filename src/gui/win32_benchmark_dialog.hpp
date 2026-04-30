#pragma once

#include "win32_config_dialog.hpp"

#include <windows.h>

namespace ibmbrute_gui {

bool run_benchmark_dialog(HWND owner, LaunchConfig& config);

}  // namespace ibmbrute_gui
