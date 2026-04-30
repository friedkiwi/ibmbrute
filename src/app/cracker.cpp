#include "app.hpp"

#include "../cuda/cuda_backend.hpp"
#include "../metal/metal_backend.hpp"

#include <atomic>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <thread>

namespace ibmbrute_app {

volatile std::sig_atomic_t g_stop = 0;

namespace {

cuda_backend::PlanData build_cuda_plan(const std::vector<Pattern>& plan) {
    cuda_backend::PlanData data;
    std::uint64_t start = 0;
    for (const auto& pattern : plan) {
        cuda_backend::PlanPattern desc;
        desc.start = start;
        desc.length = static_cast<std::uint32_t>(pattern.charsets.size());
        desc.offset_index = static_cast<std::uint32_t>(data.radices.size());
        for (const auto& charset : pattern.charsets) {
            data.charset_offsets.push_back(static_cast<std::uint32_t>(data.charset_bytes.size()));
            data.radices.push_back(static_cast<std::uint32_t>(charset.size()));
            for (char ch : charset) {
                data.charset_bytes.push_back(dst::ebcdic8(std::string(1, ch))[0]);
            }
        }
        data.patterns.push_back(desc);
        start += pattern.total;
    }
    return data;
}

void emit_match_line(const std::string& user, const std::string& password, const std::string& target_hex) {
    static std::mutex output_mutex;
    std::lock_guard<std::mutex> lock(output_mutex);
    std::cout << user << ':' << password << " -> " << target_hex << '\n' << std::flush;
}

}  // namespace

void on_signal(int) {
    g_stop = 1;
}

CrackOutcome crack_target(const TargetEntry& target,
                          const std::vector<Pattern>& plan,
                          const Config& cfg,
                          const std::string& fingerprint,
                          const std::string& session_path,
                          std::size_t target_index,
                          std::size_t target_count,
                          std::uint64_t start_position,
                          std::uint64_t total_work,
                          std::size_t thread_count) {
    constexpr std::uint64_t kIdle = std::numeric_limits<std::uint64_t>::max();
    CrackOutcome outcome;
    if (start_position >= total_work) {
        outcome.checkpoint = total_work;
        return outcome;
    }

    std::atomic<std::uint64_t> next_index(start_position);
    std::atomic<std::uint64_t> processed(start_position);
    std::atomic<std::size_t> finished_threads(0);
    std::atomic<bool> found(false);
    std::vector<std::atomic<std::uint64_t>> current(thread_count);
    for (auto& slot : current) {
        slot.store(kIdle, std::memory_order_relaxed);
    }

    std::vector<std::string> found_passwords;
    std::mutex found_mutex;
    std::vector<std::thread> workers;
    workers.reserve(thread_count);

    for (std::size_t tid = 0; tid < thread_count; ++tid) {
        workers.emplace_back([&, tid] {
            while (!g_stop && (cfg.keep_going || !found.load(std::memory_order_acquire))) {
                const std::uint64_t idx = next_index.fetch_add(1, std::memory_order_relaxed);
                if (idx >= total_work) {
                    break;
                }

                current[tid].store(idx, std::memory_order_release);
                if (g_stop || found.load(std::memory_order_acquire)) {
                    break;
                }

                const std::string candidate = candidate_for_index(plan, idx);
                processed.fetch_add(1, std::memory_order_relaxed);
                if (dst::hash_password(candidate, target.user) == target.target) {
                    {
                        std::lock_guard<std::mutex> lock(found_mutex);
                        found_passwords.push_back(candidate);
                        if (cfg.keep_going) {
                            emit_match_line(target.user, candidate, target.target_hex);
                        }
                        if (!cfg.keep_going) {
                            found.store(true, std::memory_order_release);
                        }
                    }
                    if (!cfg.keep_going) {
                        break;
                    }
                }
                current[tid].store(kIdle, std::memory_order_release);
            }
            current[tid].store(kIdle, std::memory_order_release);
            finished_threads.fetch_add(1, std::memory_order_release);
        });
    }

    auto started = std::chrono::steady_clock::now();
    auto last_status = started;
    auto last_save = started;

    auto checkpoint_from_state = [&]() -> std::uint64_t {
        std::uint64_t checkpoint = next_index.load(std::memory_order_acquire);
        for (const auto& slot : current) {
            const auto value = slot.load(std::memory_order_acquire);
            if (value < checkpoint) {
                checkpoint = value;
            }
        }
        return checkpoint > total_work ? total_work : checkpoint;
    };

    auto save_state = [&](bool complete, std::size_t next_target_index, std::uint64_t checkpoint) {
        save_session_state(session_path,
                           cfg,
                           fingerprint,
                           next_target_index,
                           checkpoint,
                           complete,
                           target.user,
                           target.target_hex);
    };

    save_state(false, target_index, start_position);

    while (finished_threads.load(std::memory_order_acquire) < thread_count) {
        if (g_stop) {
            outcome.interrupted = true;
            break;
        }
        if (!cfg.keep_going && found.load(std::memory_order_acquire)) {
            outcome.found = true;
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const auto now = std::chrono::steady_clock::now();
        const std::uint64_t checkpoint = checkpoint_from_state();
        const std::uint64_t completed = processed.load(std::memory_order_acquire);
        const double elapsed = std::chrono::duration<double>(now - started).count();

        if (cfg.status && elapsed >= static_cast<double>(cfg.status_interval) &&
            now - last_status >= std::chrono::seconds(static_cast<int>(cfg.status_interval))) {
            const double rate = completed / std::max(elapsed, 0.001);
            const double remaining = total_work > completed ? static_cast<double>(total_work - completed) / rate : 0.0;
            std::cerr << "\r"
                      << "target " << (target_index + 1) << '/' << target_count
                      << " " << target.user << ':' << target.target_hex
                      << " progress " << format_number(completed) << '/' << format_number(total_work)
                      << " (" << std::fixed << std::setprecision(2)
                      << (100.0 * static_cast<double>(completed) / static_cast<double>(total_work)) << "%)"
                      << " " << format_rate(rate) << " c/s"
                      << " eta " << format_duration(remaining)
                      << " current=" << (checkpoint < total_work ? candidate_for_index(plan, checkpoint) : "done")
                      << std::flush;
            last_status = now;
        }

        if (std::chrono::duration<double>(now - last_save).count() >= static_cast<double>(cfg.status_interval)) {
            save_state(false, target_index, checkpoint);
            last_save = now;
        }
    }

    if (g_stop) {
        outcome.interrupted = true;
    }
    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    outcome.checkpoint = checkpoint_from_state();
    {
        std::lock_guard<std::mutex> lock(found_mutex);
        outcome.passwords = found_passwords;
    }
    outcome.found = !outcome.passwords.empty();
    if (outcome.found && !cfg.keep_going) {
        save_state(true, target_index + 1, 0);
    } else if (outcome.interrupted) {
        save_state(false, target_index, outcome.checkpoint);
    } else {
        save_state(false, target_index + 1, 0);
    }

    if (cfg.status) {
        std::cerr << '\r' << std::string(160, ' ') << '\r';
    }
    return outcome;
}

CrackOutcome crack_target_metal(const TargetEntry& target,
                                const std::vector<Pattern>& plan,
                                const Config& cfg,
                                const std::string& fingerprint,
                                const std::string& session_path,
                                std::size_t target_index,
                                std::size_t target_count,
                                std::uint64_t start_position,
                                std::uint64_t total_work) {
    CrackOutcome outcome;
    if (start_position >= total_work) {
        outcome.checkpoint = total_work;
        return outcome;
    }
    if (!metal_backend::available()) {
        throw std::runtime_error("metal engine selected but Metal is not available at runtime");
    }

    const std::size_t batch_limit = metal_backend::batch_size();
    if (batch_limit == 0) {
        throw std::runtime_error("metal batch size resolved to zero");
    }

    const dst::Block8 user_block = dst::ebcdic8(target.user);
    std::vector<dst::Block8> encoded_candidates;
    encoded_candidates.reserve(batch_limit);
    std::vector<std::string> found_passwords;
    auto started = std::chrono::steady_clock::now();
    auto last_status = started;
    auto last_save = started;

    auto save_state = [&](bool complete, std::size_t next_target_index, std::uint64_t checkpoint) {
        save_session_state(session_path,
                           cfg,
                           fingerprint,
                           next_target_index,
                           checkpoint,
                           complete,
                           target.user,
                           target.target_hex);
    };

    save_state(false, target_index, start_position);
    std::uint64_t processed = start_position;
    while (processed < total_work) {
        if (g_stop) {
            outcome.interrupted = true;
            break;
        }

        const std::uint64_t batch_count = std::min<std::uint64_t>(batch_limit, total_work - processed);
        encoded_candidates.clear();
        encoded_candidates.reserve(static_cast<std::size_t>(batch_count));
        for (std::uint64_t offset = 0; offset < batch_count; ++offset) {
            encoded_candidates.push_back(dst::ebcdic8(candidate_for_index(plan, processed + offset)));
        }

        const std::uint64_t batch_start = processed;
        const std::vector<std::size_t> match_indices =
            metal_backend::crack_batch_matches(encoded_candidates, user_block, target.target);
        processed += batch_count;

        if (!match_indices.empty()) {
            for (std::size_t match_index : match_indices) {
                const std::string password = candidate_for_index(plan, batch_start + match_index);
                found_passwords.push_back(password);
                if (cfg.keep_going) {
                    emit_match_line(target.user, password, target.target_hex);
                }
            }
            if (!cfg.keep_going) {
                outcome.found = true;
                outcome.passwords = found_passwords;
                outcome.checkpoint = processed;
                save_state(true, target_index + 1, 0);
                break;
            }
        }

        const auto now = std::chrono::steady_clock::now();
        const std::uint64_t checkpoint = processed;
        const std::uint64_t completed = processed - start_position;
        const double elapsed = std::chrono::duration<double>(now - started).count();

        if (cfg.status && elapsed >= static_cast<double>(cfg.status_interval) &&
            now - last_status >= std::chrono::seconds(static_cast<int>(cfg.status_interval))) {
            const double rate = completed / std::max(elapsed, 0.001);
            const double remaining = total_work > processed ? static_cast<double>(total_work - processed) / rate : 0.0;
            std::cerr << "\r"
                      << "target " << (target_index + 1) << '/' << target_count
                      << " " << target.user << ':' << target.target_hex
                      << " progress " << format_number(completed) << '/' << format_number(total_work)
                      << " (" << std::fixed << std::setprecision(2)
                      << (100.0 * static_cast<double>(completed) / static_cast<double>(total_work)) << "%)"
                      << " " << format_rate(rate) << " c/s"
                      << " eta " << format_duration(remaining)
                      << " current=" << (checkpoint < total_work ? candidate_for_index(plan, checkpoint) : "done")
                      << std::flush;
            last_status = now;
        }

        if (std::chrono::duration<double>(now - last_save).count() >= static_cast<double>(cfg.status_interval)) {
            save_state(false, target_index, checkpoint);
            last_save = now;
        }
    }

    if (g_stop) {
        outcome.interrupted = true;
    }
    outcome.checkpoint = processed;
    outcome.passwords = found_passwords;
    outcome.found = !outcome.passwords.empty();
    if (outcome.found && !cfg.keep_going) {
        save_state(true, target_index + 1, 0);
    } else if (outcome.interrupted) {
        save_state(false, target_index, processed);
    } else {
        save_state(false, target_index + 1, 0);
    }

    if (cfg.status) {
        std::cerr << '\r' << std::string(160, ' ') << '\r';
    }
    return outcome;
}

CrackOutcome crack_target_cuda(const TargetEntry& target,
                               const std::vector<Pattern>& plan,
                               const Config& cfg,
                               const std::string& fingerprint,
                               const std::string& session_path,
                               std::size_t target_index,
                               std::size_t target_count,
                               std::uint64_t start_position,
                               std::uint64_t total_work) {
    CrackOutcome outcome;
    if (start_position >= total_work) {
        outcome.checkpoint = total_work;
        return outcome;
    }
    if (!cuda_backend::available()) {
        throw std::runtime_error("cuda engine selected but CUDA is not available at runtime");
    }
    const std::size_t batch_limit = cuda_backend::batch_size();
    if (batch_limit == 0) {
        throw std::runtime_error("cuda batch size resolved to zero");
    }

    const dst::Block8 user_block = dst::ebcdic8(target.user);
    const cuda_backend::PlanData cuda_plan = build_cuda_plan(plan);
    cuda_backend::prepare_target(cuda_plan, user_block, target.target);
    std::vector<std::string> found_passwords;
    auto started = std::chrono::steady_clock::now();
    auto last_status = started;
    auto last_save = started;

    auto save_state = [&](bool complete, std::size_t next_target_index, std::uint64_t checkpoint) {
        save_session_state(session_path,
                           cfg,
                           fingerprint,
                           next_target_index,
                           checkpoint,
                           complete,
                           target.user,
                           target.target_hex);
    };

    save_state(false, target_index, start_position);
    std::uint64_t processed = start_position;
    while (processed < total_work) {
        if (g_stop) {
            outcome.interrupted = true;
            break;
        }

        const std::uint64_t batch_count = std::min<std::uint64_t>(batch_limit, total_work - processed);
        const std::uint64_t batch_start = processed;
        const std::vector<std::size_t> match_indices =
            cuda_backend::crack_batch_matches(batch_start, static_cast<std::size_t>(batch_count), cfg.keep_going);
        processed += batch_count;

        if (!match_indices.empty()) {
            for (std::size_t match_index : match_indices) {
                const std::string password = candidate_for_index(plan, batch_start + match_index);
                found_passwords.push_back(password);
                if (cfg.keep_going) {
                    emit_match_line(target.user, password, target.target_hex);
                }
            }
            if (!cfg.keep_going) {
                outcome.found = true;
                outcome.passwords = found_passwords;
                outcome.checkpoint = processed;
                save_state(true, target_index + 1, 0);
                break;
            }
        }

        const auto now = std::chrono::steady_clock::now();
        const std::uint64_t checkpoint = processed;
        const std::uint64_t completed = processed - start_position;
        const double elapsed = std::chrono::duration<double>(now - started).count();
        if (cfg.status && elapsed >= static_cast<double>(cfg.status_interval) &&
            now - last_status >= std::chrono::seconds(static_cast<int>(cfg.status_interval))) {
            const double rate = completed / std::max(elapsed, 0.001);
            const double remaining = total_work > processed ? static_cast<double>(total_work - processed) / rate : 0.0;
            std::cerr << "\r"
                      << "target " << (target_index + 1) << '/' << target_count
                      << " " << target.user << ':' << target.target_hex
                      << " progress " << format_number(completed) << '/' << format_number(total_work)
                      << " (" << std::fixed << std::setprecision(2)
                      << (100.0 * static_cast<double>(completed) / static_cast<double>(total_work)) << "%)"
                      << " " << format_rate(rate) << " c/s"
                      << " eta " << format_duration(remaining)
                      << " current=" << (checkpoint < total_work ? candidate_for_index(plan, checkpoint) : "done")
                      << std::flush;
            last_status = now;
        }

        if (std::chrono::duration<double>(now - last_save).count() >= static_cast<double>(cfg.status_interval)) {
            save_state(false, target_index, checkpoint);
            last_save = now;
        }
    }

    if (g_stop) {
        outcome.interrupted = true;
    }
    outcome.checkpoint = processed;
    outcome.passwords = found_passwords;
    outcome.found = !outcome.passwords.empty();
    if (outcome.found && !cfg.keep_going) {
        save_state(true, target_index + 1, 0);
    } else if (outcome.interrupted) {
        save_state(false, target_index, processed);
    } else {
        save_state(false, target_index + 1, 0);
    }

    if (cfg.status) {
        std::cerr << '\r' << std::string(160, ' ') << '\r';
    }
    return outcome;
}

}  // namespace ibmbrute_app
