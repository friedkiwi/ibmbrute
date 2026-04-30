#include "win32_benchmark_dialog.hpp"

#include "../app/app.hpp"
#include "../cuda/cuda_backend.hpp"
#include "resource.h"

#include <commctrl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

namespace ibmbrute_gui {

namespace {

constexpr UINT_PTR kBenchmarkTimerId = 1;
constexpr UINT WM_APP_BENCHMARK_FINISHED = WM_APP + 2;

struct BenchmarkResultPayload {
    cuda_backend::BenchmarkResult result;
    std::string error;
    bool cancelled = false;
};

struct DialogState {
    LaunchConfig* config = nullptr;
    HWND progress_bar = nullptr;
    HWND status_edit = nullptr;
    HWND best_edit = nullptr;
    std::thread worker;
    std::atomic<std::size_t> completed{0};
    std::atomic<std::size_t> total{0};
    std::atomic<std::size_t> current_batch_size{0};
    std::atomic<unsigned int> current_thread_count{0};
    std::atomic<std::size_t> best_batch_size{0};
    std::atomic<unsigned int> best_thread_count{0};
    std::atomic<bool> cancel_requested{false};
};

std::wstring widen_ascii(const std::string& value)
{
    return std::wstring(value.begin(), value.end());
}

void set_text(HWND control, const std::wstring& text)
{
    SetWindowTextW(control, text.c_str());
}

std::wstring status_text(const DialogState& state)
{
    std::wostringstream oss;
    oss << L"Testing batch=" << state.current_batch_size.load(std::memory_order_relaxed)
        << L", threads=" << state.current_thread_count.load(std::memory_order_relaxed)
        << L" (" << state.completed.load(std::memory_order_relaxed)
        << L"/" << state.total.load(std::memory_order_relaxed) << L")";
    return oss.str();
}

std::wstring best_text(const DialogState& state)
{
    const std::size_t batch = state.best_batch_size.load(std::memory_order_relaxed);
    const unsigned int threads = state.best_thread_count.load(std::memory_order_relaxed);
    if (batch == 0 || threads == 0) {
        return L"Best so far: none";
    }

    std::wostringstream oss;
    oss << L"Best so far: batch=" << batch << L", threads=" << threads;
    return oss.str();
}

void update_controls(DialogState& state)
{
    const std::size_t total = state.total.load(std::memory_order_relaxed);
    const std::size_t completed = state.completed.load(std::memory_order_relaxed);
    const int value = (total == 0) ? 0 : static_cast<int>(std::min<std::size_t>((completed * 1000u) / total, 1000u));
    SendMessageW(state.progress_bar, PBM_SETPOS, static_cast<WPARAM>(value), 0);
    set_text(state.status_edit, status_text(state));
    set_text(state.best_edit, best_text(state));
}

bool benchmark_progress_callback(const cuda_backend::BenchmarkProgress& progress, void* context)
{
    DialogState* state = static_cast<DialogState*>(context);
    state->completed.store(progress.completed, std::memory_order_relaxed);
    state->total.store(progress.total, std::memory_order_relaxed);
    state->current_batch_size.store(progress.current_batch_size, std::memory_order_relaxed);
    state->current_thread_count.store(progress.current_thread_count, std::memory_order_relaxed);
    state->best_batch_size.store(progress.best_batch_size, std::memory_order_relaxed);
    state->best_thread_count.store(progress.best_thread_count, std::memory_order_relaxed);
    return !state->cancel_requested.load(std::memory_order_relaxed);
}

INT_PTR CALLBACK dialog_proc(HWND hwnd, UINT message, WPARAM w_param, LPARAM l_param)
{
    DialogState* state = reinterpret_cast<DialogState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (message) {
        case WM_INITDIALOG: {
            state = reinterpret_cast<DialogState*>(l_param);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            state->progress_bar = GetDlgItem(hwnd, IDC_BENCHMARK_PROGRESS);
            state->status_edit = GetDlgItem(hwnd, IDC_BENCHMARK_STATUS);
            state->best_edit = GetDlgItem(hwnd, IDC_BENCHMARK_BEST);
            SendMessageW(state->progress_bar, PBM_SETRANGE32, 0, 1000);
            set_text(state->status_edit, L"Preparing benchmark...");
            set_text(state->best_edit, L"Best so far: none");

            state->worker = std::thread([hwnd, state]() {
                std::unique_ptr<BenchmarkResultPayload> payload(new BenchmarkResultPayload);
                try {
                    payload->result = cuda_backend::benchmark_with_progress(benchmark_progress_callback, state);
                    payload->cancelled = state->cancel_requested.load(std::memory_order_relaxed);
                } catch (const std::exception& ex) {
                    payload->error = ex.what();
                }

                PostMessageW(hwnd,
                             WM_APP_BENCHMARK_FINISHED,
                             0,
                             reinterpret_cast<LPARAM>(payload.release()));
            });

            SetTimer(hwnd, kBenchmarkTimerId, 100, nullptr);
            return TRUE;
        }

        case WM_TIMER:
            if (state != nullptr && w_param == kBenchmarkTimerId) {
                update_controls(*state);
                return TRUE;
            }
            break;

        case WM_COMMAND:
            if (LOWORD(w_param) == IDCANCEL && state != nullptr) {
                state->cancel_requested.store(true, std::memory_order_relaxed);
                set_text(state->status_edit, L"Cancelling benchmark...");
                return TRUE;
            }
            break;

        case WM_CLOSE:
            if (state != nullptr) {
                state->cancel_requested.store(true, std::memory_order_relaxed);
                set_text(state->status_edit, L"Cancelling benchmark...");
                return TRUE;
            }
            break;

        case WM_APP_BENCHMARK_FINISHED:
            if (state != nullptr) {
                std::unique_ptr<BenchmarkResultPayload> payload(reinterpret_cast<BenchmarkResultPayload*>(l_param));
                KillTimer(hwnd, kBenchmarkTimerId);
                if (state->worker.joinable()) {
                    state->worker.join();
                }
                update_controls(*state);

                if (!payload->error.empty()) {
                    MessageBoxW(hwnd, widen_ascii(payload->error).c_str(), L"CUDA Benchmark", MB_ICONERROR | MB_OK);
                    EndDialog(hwnd, IDCANCEL);
                    return TRUE;
                }
                if (payload->cancelled) {
                    EndDialog(hwnd, IDCANCEL);
                    return TRUE;
                }
                if (state->config != nullptr) {
                    state->config->cuda_batch_size = payload->result.batch_size;
                    state->config->cuda_thread_count = payload->result.thread_count;
                }
                EndDialog(hwnd, IDOK);
                return TRUE;
            }
            break;
    }

    return FALSE;
}

}  // namespace

bool run_benchmark_dialog(HWND owner, LaunchConfig& config)
{
    DialogState state;
    state.config = &config;
    HINSTANCE instance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(owner, GWLP_HINSTANCE));
    return DialogBoxParamW(instance,
                           MAKEINTRESOURCEW(IDD_BENCHMARK_DIALOG),
                           owner,
                           dialog_proc,
                           reinterpret_cast<LPARAM>(&state)) == IDOK;
}

}  // namespace ibmbrute_gui
