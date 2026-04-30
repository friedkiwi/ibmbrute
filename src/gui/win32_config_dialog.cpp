#include "win32_config_dialog.hpp"

#include "../cuda/cuda_backend.hpp"
#include "resource.h"
#include "win32_benchmark_dialog.hpp"

#include <commctrl.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace ibmbrute_gui {

namespace {

struct DialogState {
    LaunchConfig* config = nullptr;
};

std::wstring format_u64(std::size_t value)
{
    return std::to_wstring(static_cast<unsigned long long>(value));
}

std::wstring format_u32(unsigned int value)
{
    return std::to_wstring(static_cast<unsigned long>(value));
}

int select_combo_value(HWND combo, const std::wstring& value)
{
    const int index = static_cast<int>(SendMessageW(combo, CB_FINDSTRINGEXACT, static_cast<WPARAM>(-1),
                                                    reinterpret_cast<LPARAM>(value.c_str())));
    if (index >= 0) {
        SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(index), 0);
    }
    return index;
}

std::wstring selected_combo_text(HWND combo)
{
    const int index = static_cast<int>(SendMessageW(combo, CB_GETCURSEL, 0, 0));
    if (index == CB_ERR) {
        return L"";
    }

    const LRESULT length_result = SendMessageW(combo, CB_GETLBTEXTLEN, static_cast<WPARAM>(index), 0);
    if (length_result == CB_ERR) {
        return L"";
    }

    const int length = static_cast<int>(length_result);
    std::wstring value(static_cast<std::size_t>(length) + 1, L'\0');
    SendMessageW(combo, CB_GETLBTEXT, static_cast<WPARAM>(index), reinterpret_cast<LPARAM>(value.data()));
    value.resize(static_cast<std::size_t>(length));
    return value;
}

bool parse_size(const std::wstring& text, std::size_t* value)
{
    if (text.empty()) {
        return false;
    }
    *value = static_cast<std::size_t>(std::stoull(text));
    return true;
}

void show_message(HWND hwnd, UINT flags, const std::wstring& text)
{
    MessageBoxW(hwnd, text.c_str(), L"CUDA Parameters", flags);
}

INT_PTR CALLBACK dialog_proc(HWND hwnd, UINT message, WPARAM w_param, LPARAM l_param)
{
    DialogState* state = reinterpret_cast<DialogState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (message) {
        case WM_INITDIALOG: {
            state = reinterpret_cast<DialogState*>(l_param);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));

            HWND batch_combo = GetDlgItem(hwnd, IDC_BATCH_SIZE_EDIT);
            HWND thread_combo = GetDlgItem(hwnd, IDC_THREAD_COUNT_EDIT);

            for (std::size_t value : cuda_backend::benchmark_batch_candidates()) {
                const std::wstring label = format_u64(value);
                SendMessageW(batch_combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
            }
            for (unsigned int value : cuda_backend::benchmark_thread_candidates()) {
                const std::wstring label = format_u32(value);
                SendMessageW(thread_combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
            }

            if (state != nullptr && state->config != nullptr) {
                const std::size_t batch =
                    state->config->cuda_batch_size == 0 ? cuda_backend::batch_size() : state->config->cuda_batch_size;
                const unsigned int threads = state->config->cuda_thread_count == 0 ? cuda_backend::thread_count()
                                                                                    : state->config->cuda_thread_count;
                if (select_combo_value(batch_combo, format_u64(batch)) < 0) {
                    SendMessageW(batch_combo, CB_SETCURSEL, 0, 0);
                }
                if (select_combo_value(thread_combo, format_u32(threads)) < 0) {
                    SendMessageW(thread_combo, CB_SETCURSEL, 0, 0);
                }
            }
            return TRUE;
        }

        case WM_COMMAND:
            switch (LOWORD(w_param)) {
                case IDC_AUTODETECT_BUTTON:
                    if (state != nullptr && state->config != nullptr && run_benchmark_dialog(hwnd, *state->config)) {
                        select_combo_value(GetDlgItem(hwnd, IDC_BATCH_SIZE_EDIT), format_u64(state->config->cuda_batch_size));
                        select_combo_value(GetDlgItem(hwnd, IDC_THREAD_COUNT_EDIT), format_u32(state->config->cuda_thread_count));
                    }
                    return TRUE;

                case IDOK: {
                    if (state == nullptr || state->config == nullptr) {
                        EndDialog(hwnd, IDCANCEL);
                        return TRUE;
                    }

                    std::size_t batch_size = 0;
                    unsigned int thread_count = 0;
                    if (!parse_size(selected_combo_text(GetDlgItem(hwnd, IDC_BATCH_SIZE_EDIT)), &batch_size)) {
                        show_message(hwnd,
                                     MB_ICONERROR | MB_OK,
                                     L"Select a valid batch size.");
                        return TRUE;
                    }
                    const std::wstring thread_text = selected_combo_text(GetDlgItem(hwnd, IDC_THREAD_COUNT_EDIT));
                    if (thread_text.empty()) {
                        show_message(hwnd,
                                     MB_ICONERROR | MB_OK,
                                     L"Select a valid thread count.");
                        return TRUE;
                    }
                    thread_count = static_cast<unsigned int>(std::stoul(thread_text));

                    state->config->cuda_batch_size = batch_size;
                    state->config->cuda_thread_count = thread_count;
                    EndDialog(hwnd, IDOK);
                    return TRUE;
                }

                case IDCANCEL:
                    EndDialog(hwnd, IDCANCEL);
                    return TRUE;
            }
            break;
    }

    return FALSE;
}

}  // namespace

bool show_config_dialog(HWND owner, LaunchConfig& config)
{
    DialogState state;
    state.config = &config;
    HINSTANCE instance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(owner, GWLP_HINSTANCE));
    return DialogBoxParamW(instance,
                           MAKEINTRESOURCEW(IDD_CONFIG_DIALOG),
                           owner,
                           dialog_proc,
                           reinterpret_cast<LPARAM>(&state)) == IDOK;
}

}  // namespace ibmbrute_gui
