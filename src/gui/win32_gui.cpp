#include "../app/app.hpp"
#include "../cuda/cuda_backend.hpp"
#include "../dst_hash.hpp"

#include "gui_resources.h"
#include "win32_config_dialog.hpp"

#include <windows.h>
#include <commctrl.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cwctype>
#include <chrono>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr UINT_PTR kProgressTimerId = 1;
constexpr UINT WM_APP_CRACK_FINISHED = WM_APP + 1;
constexpr const wchar_t* kRegistryPath = L"Software\\ibmbrute\\win32";

struct WorkerResult {
    ibmbrute_app::CrackOutcome outcome;
    std::string error;
    std::string user;
    std::string target_hex;
    std::string session_path;
    std::uint64_t total_work = 0;
    double elapsed_seconds = 0.0;
};

struct AppState {
    HWND hwnd = nullptr;
    HWND gpu_combo = nullptr;
    HWND username_edit = nullptr;
    HWND hash_edit = nullptr;
    HWND progress_bar = nullptr;
    HWND status_edit = nullptr;
    HWND crack_button = nullptr;
    std::vector<cuda_backend::DeviceInfo> devices;
    std::thread worker;
    std::vector<ibmbrute_app::Pattern> active_plan;
    std::string active_user;
    std::string active_target_hex;
    ibmbrute_gui::LaunchConfig launch_config;
    std::atomic<std::uint64_t> processed{0};
    std::atomic<std::uint64_t> total_work{0};
    std::chrono::steady_clock::time_point run_started{};
    bool running = false;
    bool close_when_idle = false;
};

std::wstring widen_ascii(const std::string& value)
{
    return std::wstring(value.begin(), value.end());
}

std::wstring trim_copy(const std::wstring& value)
{
    std::size_t start = 0;
    while (start < value.size() && iswspace(value[start]) != 0) {
        ++start;
    }

    std::size_t end = value.size();
    while (end > start && iswspace(value[end - 1]) != 0) {
        --end;
    }
    return value.substr(start, end - start);
}

std::wstring get_window_text(HWND control)
{
    const int length = GetWindowTextLengthW(control);
    std::wstring value(static_cast<std::size_t>(length) + 1, L'\0');
    if (length >= 0) {
        GetWindowTextW(control, value.data(), length + 1);
    }
    value.resize(static_cast<std::size_t>(length));
    return value;
}

std::string narrow_ascii(const std::wstring& value)
{
    std::string out;
    out.reserve(value.size());
    for (wchar_t ch : value) {
        if (ch < 0 || ch > 0x7f) {
            throw std::runtime_error("only ASCII input is supported");
        }
        out.push_back(static_cast<char>(ch));
    }
    return out;
}

void show_message(HWND hwnd, UINT flags, const std::wstring& text, const wchar_t* title)
{
    MessageBoxW(hwnd, text.c_str(), title, flags);
}

bool read_registry_dword(const wchar_t* name, DWORD* value)
{
    DWORD type = 0;
    DWORD size = sizeof(*value);
    return RegGetValueW(HKEY_CURRENT_USER,
                        kRegistryPath,
                        name,
                        RRF_RT_REG_DWORD,
                        &type,
                        value,
                        &size) == ERROR_SUCCESS;
}

void write_registry_dword(const wchar_t* name, DWORD value)
{
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
                        kRegistryPath,
                        0,
                        nullptr,
                        REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE,
                        nullptr,
                        &key,
                        nullptr) != ERROR_SUCCESS) {
        return;
    }

    RegSetValueExW(key,
                   name,
                   0,
                   REG_DWORD,
                   reinterpret_cast<const BYTE*>(&value),
                   static_cast<DWORD>(sizeof(value)));
    RegCloseKey(key);
}

void load_persisted_settings(AppState& state)
{
    DWORD value = 0;
    if (read_registry_dword(L"GpuIndex", &value)) {
        for (std::size_t i = 0; i < state.devices.size(); ++i) {
            if (state.devices[i].index == static_cast<int>(value)) {
                SendMessageW(state.gpu_combo, CB_SETCURSEL, static_cast<WPARAM>(i), 0);
                break;
            }
        }
    }

    if (read_registry_dword(L"CudaBatchSize", &value) && value > 0) {
        state.launch_config.cuda_batch_size = static_cast<std::size_t>(value);
    }
    if (read_registry_dword(L"CudaThreadCount", &value) && value > 0) {
        state.launch_config.cuda_thread_count = static_cast<unsigned int>(value);
    }
}

void persist_gpu_selection(const AppState& state)
{
    const int selected = static_cast<int>(SendMessageW(state.gpu_combo, CB_GETCURSEL, 0, 0));
    if (selected == CB_ERR || selected < 0 || static_cast<std::size_t>(selected) >= state.devices.size()) {
        return;
    }
    write_registry_dword(L"GpuIndex", static_cast<DWORD>(state.devices[static_cast<std::size_t>(selected)].index));
}

void persist_launch_config(const ibmbrute_gui::LaunchConfig& config)
{
    if (config.cuda_batch_size != 0) {
        write_registry_dword(L"CudaBatchSize", static_cast<DWORD>(config.cuda_batch_size));
    }
    if (config.cuda_thread_count != 0) {
        write_registry_dword(L"CudaThreadCount", static_cast<DWORD>(config.cuda_thread_count));
    }
}

void set_status_text(AppState& state, const std::wstring& text)
{
    SetWindowTextW(state.status_edit, text.c_str());
}

std::wstring gpu_label(const cuda_backend::DeviceInfo& device)
{
    std::wostringstream oss;
    oss << L"GPU " << device.index << L": " << widen_ascii(device.name)
        << L" (SM " << device.major << L'.' << device.minor
        << L", " << (device.total_global_mem / (1024ull * 1024ull)) << L" MiB)";
    return oss.str();
}

std::wstring format_elapsed_hms(double seconds)
{
    if (seconds < 0) {
        seconds = 0;
    }
    const std::uint64_t total = static_cast<std::uint64_t>(seconds + 0.5);
    const std::uint64_t hours = total / 3600;
    const std::uint64_t minutes = (total % 3600) / 60;
    const std::uint64_t secs = total % 60;

    std::wostringstream oss;
    oss << hours << L"h " << minutes << L"m " << secs << L"s";
    return oss.str();
}

bool validate_inputs(AppState& state, ibmbrute_app::Config& cfg, std::wstring* error_text)
{
    const int selected = static_cast<int>(SendMessageW(state.gpu_combo, CB_GETCURSEL, 0, 0));
    if (selected == CB_ERR || selected < 0 || static_cast<std::size_t>(selected) >= state.devices.size()) {
        if (error_text != nullptr) {
            *error_text = L"Select a CUDA-capable NVIDIA GPU.";
        }
        return false;
    }

    const std::wstring raw_username = get_window_text(state.username_edit);
    const std::wstring trimmed_username = trim_copy(raw_username);
    if (trimmed_username.empty()) {
        if (error_text != nullptr) {
            *error_text = L"Enter a username.";
        }
        return false;
    }

    std::string username;
    try {
        username = narrow_ascii(raw_username);
    } catch (const std::exception&) {
        if (error_text != nullptr) {
            *error_text = L"Username must contain only ASCII characters.";
        }
        return false;
    }
    std::transform(username.begin(), username.end(), username.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    if (username.size() < 3) {
        if (error_text != nullptr) {
            *error_text = L"Username must be at least 3 characters.";
        }
        return false;
    }
    if (username.size() > 10) {
        if (error_text != nullptr) {
            *error_text = L"Username must be at most 10 characters.";
        }
        return false;
    }
    if (!std::isalpha(static_cast<unsigned char>(username.front()))) {
        if (error_text != nullptr) {
            *error_text = L"Username must start with a letter.";
        }
        return false;
    }
    if (!std::all_of(username.begin(), username.end(), [](unsigned char ch) {
            return std::isupper(ch) != 0 || std::isdigit(ch) != 0;
        })) {
        if (error_text != nullptr) {
            *error_text = L"Username may only contain A-Z and 0-9.";
        }
        return false;
    }
    try {
        static_cast<void>(dst::ebcdic8(username));
    } catch (const std::exception& ex) {
        if (error_text != nullptr) {
            *error_text = widen_ascii(ex.what());
        }
        return false;
    }

    std::wstring hash_wide = trim_copy(get_window_text(state.hash_edit));
    std::transform(hash_wide.begin(), hash_wide.end(), hash_wide.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(towupper(ch));
    });

    std::string hash;
    try {
        hash = narrow_ascii(hash_wide);
    } catch (const std::exception&) {
        if (error_text != nullptr) {
            *error_text = L"Hash must contain only ASCII hexadecimal characters.";
        }
        return false;
    }

    if (hash.size() != 16) {
        if (error_text != nullptr) {
            *error_text = L"Hash must be exactly 16 hexadecimal characters.";
        }
        return false;
    }
    if (!std::all_of(hash.begin(), hash.end(), [](unsigned char ch) { return std::isxdigit(ch) != 0; })) {
        if (error_text != nullptr) {
            *error_text = L"Hash must contain only hexadecimal characters.";
        }
        return false;
    }
    try {
        static_cast<void>(dst::hex_decode8(hash));
    } catch (const std::exception& ex) {
        if (error_text != nullptr) {
            *error_text = widen_ascii(ex.what());
        }
        return false;
    }

    cfg = ibmbrute_app::Config{};
    cfg.engine = "cuda";
    cfg.status = false;
    cfg.user = username;
    cfg.target_hex = hash;
    if (state.launch_config.cuda_batch_size != 0) {
        cfg.cuda_batch_size = state.launch_config.cuda_batch_size;
    }
    if (state.launch_config.cuda_thread_count != 0) {
        cfg.cuda_thread_count = state.launch_config.cuda_thread_count;
    }
    return true;
}

void set_running_state(AppState& state, bool running)
{
    state.running = running;
    EnableWindow(state.gpu_combo, running ? FALSE : TRUE);
    EnableWindow(state.username_edit, running ? FALSE : TRUE);
    EnableWindow(state.hash_edit, running ? FALSE : TRUE);
    SetWindowTextW(state.crack_button, running ? L"Stop" : L"Crack");
    if (running) {
        SetTimer(state.hwnd, kProgressTimerId, 100, nullptr);
    } else {
        KillTimer(state.hwnd, kProgressTimerId);
    }
}

std::wstring format_runtime_status(AppState& state)
{
    const std::uint64_t total = state.total_work.load(std::memory_order_relaxed);
    const std::uint64_t processed = state.processed.load(std::memory_order_relaxed);
    if (total == 0) {
        return L"Idle.";
    }

    const auto now = std::chrono::steady_clock::now();
    const double elapsed = std::chrono::duration<double>(now - state.run_started).count();
    const double rate = (elapsed > 0.001) ? (static_cast<double>(processed) / elapsed) : 0.0;
    const double remaining =
        (rate > 0.0 && total > processed) ? (static_cast<double>(total - processed) / rate) : 0.0;

    std::wstring current = L"done";
    if (processed < total && !state.active_plan.empty()) {
        try {
            current = widen_ascii(ibmbrute_app::candidate_for_index(state.active_plan, processed));
        } catch (const std::exception&) {
            current = L"?";
        }
    }

    std::wostringstream oss;
    oss << L"progress " << widen_ascii(ibmbrute_app::format_number(processed))
        << L"/" << widen_ascii(ibmbrute_app::format_number(total))
        << L" (" << std::fixed << std::setprecision(2)
        << (100.0 * static_cast<double>(processed) / static_cast<double>(total)) << L"%) "
        << widen_ascii(ibmbrute_app::format_rate(rate)) << L" c/s eta "
        << widen_ascii(ibmbrute_app::format_duration(remaining))
        << L" current=" << current;
    return oss.str();
}

void update_crack_button_enabled(AppState& state)
{
    if (state.running) {
        EnableWindow(state.crack_button, TRUE);
        return;
    }

    ibmbrute_app::Config cfg;
    std::wstring error_text;
    const bool valid = validate_inputs(state, cfg, &error_text);
    EnableWindow(state.crack_button, valid ? TRUE : FALSE);
    if (valid) {
        set_status_text(state, L"Ready.");
    } else if (!error_text.empty()) {
        set_status_text(state, error_text);
    } else {
        set_status_text(state, L"Enter parameters.");
    }
}

void update_progress_bar(AppState& state)
{
    const std::uint64_t total = state.total_work.load(std::memory_order_relaxed);
    const std::uint64_t processed = state.processed.load(std::memory_order_relaxed);
    const int value =
        (total == 0) ? 0 : static_cast<int>(std::min<std::uint64_t>((processed * 1000ull) / total, 1000ull));
    SendMessageW(state.progress_bar, PBM_SETPOS, static_cast<WPARAM>(value), 0);
}

void finish_worker(AppState& state, std::unique_ptr<WorkerResult> result)
{
    if (state.worker.joinable()) {
        state.worker.join();
    }
    set_running_state(state, false);
    state.processed.store(result->outcome.checkpoint, std::memory_order_relaxed);
    update_progress_bar(state);
    update_crack_button_enabled(state);

    if (!result->error.empty()) {
        set_status_text(state, widen_ascii(result->error));
        show_message(state.hwnd, MB_ICONERROR | MB_OK, widen_ascii(result->error), L"ibmbrute GPU");
    } else if (result->outcome.interrupted) {
        set_status_text(state, L"Cracking stopped. Session state was saved.");
        show_message(state.hwnd,
                     MB_ICONINFORMATION | MB_OK,
                     L"Cracking stopped. Session state was saved.",
                     L"ibmbrute GPU");
    } else if (result->outcome.found && !result->outcome.passwords.empty()) {
        const std::string& password = result->outcome.passwords.front();
        try {
            const ibmbrute_app::TargetEntry target{
                result->user, result->target_hex, dst::hex_decode8(result->target_hex)};
            if (!ibmbrute_app::password_matches_target(target, password)) {
                throw std::runtime_error("discovered password failed final verification");
            }
            ibmbrute_app::save_found_password(target, password);
        } catch (const std::exception& ex) {
            const std::wstring message = widen_ascii(ex.what());
            set_status_text(state, message);
            show_message(state.hwnd, MB_ICONERROR | MB_OK, message, L"ibmbrute GPU");
            state.active_plan.clear();
            if (state.close_when_idle) {
                EndDialog(state.hwnd, 0);
            }
            return;
        }
        const std::wstring message = L"Match found for user " + widen_ascii(result->user) +
                                     L" and hash " + widen_ascii(result->target_hex) + L" in " +
                                     format_elapsed_hms(result->elapsed_seconds) + L" -> " +
                                     widen_ascii(password);
        set_status_text(state, message);
        show_message(state.hwnd, MB_ICONINFORMATION | MB_OK, message, L"ibmbrute GPU");
    } else {
        std::wostringstream oss;
        oss << L"No match in " << widen_ascii(ibmbrute_app::format_number(result->total_work)) << L" candidates.";
        set_status_text(state, oss.str());
        show_message(state.hwnd, MB_ICONINFORMATION | MB_OK, oss.str(), L"ibmbrute GPU");
    }

    state.active_plan.clear();

    if (state.close_when_idle) {
        EndDialog(state.hwnd, 0);
    }
}

void begin_crack(AppState& state)
{
    ibmbrute_app::Config cfg;
    std::wstring error_text;
    if (!validate_inputs(state, cfg, &error_text)) {
        show_message(state.hwnd, MB_ICONERROR | MB_OK, error_text, L"ibmbrute GPU");
        update_crack_button_enabled(state);
        return;
    }

    const int selected = static_cast<int>(SendMessageW(state.gpu_combo, CB_GETCURSEL, 0, 0));
    const cuda_backend::DeviceInfo device = state.devices[static_cast<std::size_t>(selected)];

    try {
        cuda_backend::select_device(device.index);
        ibmbrute_app::apply_cuda_launch_config(cfg);
        const std::string fingerprint = ibmbrute_app::session_fingerprint(cfg);
        const std::string session_path = ibmbrute_app::resolve_session_path(cfg);
        const std::vector<ibmbrute_app::Pattern> plan = ibmbrute_app::build_plan_from_config(cfg);
        const std::vector<ibmbrute_app::TargetEntry> targets = ibmbrute_app::load_targets(cfg);
        const std::uint64_t total_work = ibmbrute_app::total_candidates(plan);

        if (targets.empty()) {
            throw std::runtime_error("no targets were loaded");
        }
        if (total_work == 0) {
            throw std::runtime_error("empty search space");
        }

        const ibmbrute_app::TargetEntry target = targets.front();
        std::string found_password;
        if (ibmbrute_app::load_found_password(target, &found_password)) {
            ibmbrute_app::save_session_state(session_path,
                                             cfg,
                                             fingerprint,
                                             1,
                                             0,
                                             true,
                                             target.user,
                                             target.target_hex);
            const std::wstring message = L"Match found for user " + widen_ascii(target.user) +
                                         L" and hash " + widen_ascii(target.target_hex) + L" in " +
                                         format_elapsed_hms(0.0) + L" -> " + widen_ascii(found_password);
            set_status_text(state, message);
            show_message(state.hwnd, MB_ICONINFORMATION | MB_OK, message, L"ibmbrute GPU");
            return;
        }
        if (ibmbrute_app::has_default_password(target)) {
            ibmbrute_app::save_found_password(target, target.user);
            ibmbrute_app::save_session_state(session_path,
                                             cfg,
                                             fingerprint,
                                             1,
                                             0,
                                             true,
                                             target.user,
                                             target.target_hex);
            const std::wstring message = L"Match found for user " + widen_ascii(target.user) +
                                         L" and hash " + widen_ascii(target.target_hex) + L" in " +
                                         format_elapsed_hms(0.0) + L" -> " + widen_ascii(target.user);
            set_status_text(state, message);
            show_message(state.hwnd, MB_ICONINFORMATION | MB_OK, message, L"ibmbrute GPU");
            return;
        }

        std::uint64_t start_position = 0;
        if (ibmbrute_app::session_file_exists(session_path)) {
            const ibmbrute_app::ResumeData restored = ibmbrute_app::load_resume(session_path);
            if (ibmbrute_app::session_should_resume(restored, cfg, fingerprint) && restored.target_index < 1) {
                const int choice = MessageBoxW(state.hwnd,
                                               L"A saved session was found for this target.\n\nResume it?",
                                               L"ibmbrute GPU",
                                               MB_ICONQUESTION | MB_YESNO);
                if (choice == IDYES) {
                    start_position = restored.position;
                }
            }
        }

        ibmbrute_app::g_stop = 0;
        state.active_plan = plan;
        state.active_user = targets.front().user;
        state.active_target_hex = targets.front().target_hex;
        state.processed.store(start_position, std::memory_order_relaxed);
        state.total_work.store(total_work, std::memory_order_relaxed);
        state.run_started = std::chrono::steady_clock::now();
        update_progress_bar(state);
        set_status_text(state, format_runtime_status(state));
        set_running_state(state, true);

        state.worker = std::thread([hwnd = state.hwnd,
                                    cfg = std::move(cfg),
                                    plan = std::move(plan),
                                    target,
                                    fingerprint,
                                    session_path,
                                    start_position,
                                    total_work,
                                    &state]() mutable {
            auto result = std::make_unique<WorkerResult>();
            const auto started = std::chrono::steady_clock::now();
            result->user = target.user;
            result->target_hex = target.target_hex;
            result->session_path = session_path;
            result->total_work = total_work;

            try {
                result->outcome = ibmbrute_app::crack_target_cuda(target,
                                                                  plan,
                                                                  cfg,
                                                                  fingerprint,
                                                                  session_path,
                                                                  0,
                                                                  1,
                                                                  start_position,
                                                                  total_work,
                                                                  [&state](std::uint64_t processed,
                                                                           std::uint64_t total) {
                                                                      state.processed.store(processed,
                                                                                            std::memory_order_relaxed);
                                                                      state.total_work.store(total,
                                                                                             std::memory_order_relaxed);
                                                                  });
            } catch (const std::exception& ex) {
                result->error = ex.what();
            }
            result->elapsed_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();

            PostMessageW(hwnd,
                         WM_APP_CRACK_FINISHED,
                         0,
                         reinterpret_cast<LPARAM>(result.release()));
        });
    } catch (const std::exception& ex) {
        show_message(state.hwnd, MB_ICONERROR | MB_OK, widen_ascii(ex.what()), L"ibmbrute GPU");
        update_crack_button_enabled(state);
    }
}

INT_PTR CALLBACK dialog_proc(HWND hwnd, UINT message, WPARAM w_param, LPARAM l_param)
{
    AppState* state = reinterpret_cast<AppState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (message) {
        case WM_INITDIALOG: {
            state = reinterpret_cast<AppState*>(l_param);
            state->hwnd = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));

            state->gpu_combo = GetDlgItem(hwnd, IDC_GPU_COMBO);
            state->username_edit = GetDlgItem(hwnd, IDC_USERNAME_EDIT);
            state->hash_edit = GetDlgItem(hwnd, IDC_HASH_EDIT);
            state->progress_bar = GetDlgItem(hwnd, IDC_PROGRESS_BAR);
            state->status_edit = GetDlgItem(hwnd, IDC_STATUS_EDIT);
            state->crack_button = GetDlgItem(hwnd, IDC_CRACK_BUTTON);

            SendMessageW(state->username_edit, EM_LIMITTEXT, 10, 0);
            SendMessageW(state->hash_edit, EM_LIMITTEXT, 16, 0);
            SendMessageW(state->progress_bar, PBM_SETRANGE32, 0, 1000);

            state->devices = cuda_backend::devices();
            if (state->devices.empty()) {
                show_message(hwnd,
                             MB_ICONERROR | MB_OK,
                             L"No supported NVIDIA GPU was detected. The GUI requires CUDA.",
                             L"ibmbrute GPU");
                EndDialog(hwnd, 1);
                return FALSE;
            }

            for (const auto& device : state->devices) {
                const std::wstring label = gpu_label(device);
                SendMessageW(state->gpu_combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
            }
            SendMessageW(state->gpu_combo, CB_SETCURSEL, 0, 0);
            load_persisted_settings(*state);
            update_progress_bar(*state);
            update_crack_button_enabled(*state);
            return TRUE;
        }

        case WM_COMMAND:
            if (state == nullptr) {
                return FALSE;
            }
            switch (LOWORD(w_param)) {
                case IDC_CONFIGURE_BUTTON:
                    if (show_config_dialog(hwnd, state->launch_config)) {
                        persist_launch_config(state->launch_config);
                    }
                    return TRUE;

                case IDC_CRACK_BUTTON:
                    if (state->running) {
                        if (MessageBoxW(hwnd,
                                        L"Stop the current cracking run?",
                                        L"ibmbrute GPU",
                                        MB_ICONQUESTION | MB_YESNO) == IDYES) {
                            ibmbrute_app::g_stop = 1;
                        }
                    } else {
                        begin_crack(*state);
                    }
                    return TRUE;

                case IDC_USERNAME_EDIT:
                case IDC_HASH_EDIT:
                case IDC_GPU_COMBO:
                    if (HIWORD(w_param) == EN_CHANGE || HIWORD(w_param) == CBN_SELCHANGE) {
                        if (LOWORD(w_param) == IDC_GPU_COMBO) {
                            persist_gpu_selection(*state);
                        }
                        update_crack_button_enabled(*state);
                    }
                    return TRUE;
            }
            break;

        case WM_TIMER:
            if (state != nullptr && w_param == kProgressTimerId) {
                update_progress_bar(*state);
                set_status_text(*state, format_runtime_status(*state));
                return TRUE;
            }
            break;

        case WM_APP_CRACK_FINISHED:
            if (state != nullptr) {
                std::unique_ptr<WorkerResult> result(reinterpret_cast<WorkerResult*>(l_param));
                finish_worker(*state, std::move(result));
                return TRUE;
            }
            break;

        case WM_CLOSE:
            if (state == nullptr) {
                EndDialog(hwnd, 0);
                return TRUE;
            }

            if (state->running) {
                if (MessageBoxW(hwnd,
                                L"Cracking is in progress. Stop and close?",
                                L"ibmbrute GPU",
                                MB_ICONQUESTION | MB_YESNO) == IDYES) {
                    state->close_when_idle = true;
                    ibmbrute_app::g_stop = 1;
                }
                return TRUE;
            }

            EndDialog(hwnd, 0);
            return TRUE;
    }

    return FALSE;
}

}  // namespace

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int)
{
    INITCOMMONCONTROLSEX controls{};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&controls);

    AppState state;
    return static_cast<int>(DialogBoxParamW(instance,
                                            MAKEINTRESOURCEW(IDD_MAIN_DIALOG),
                                            nullptr,
                                            dialog_proc,
                                            reinterpret_cast<LPARAM>(&state)));
}
