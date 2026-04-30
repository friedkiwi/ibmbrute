#include "app.hpp"

#include "../cuda/cuda_backend.hpp"
#include "../metal/metal_backend.hpp"

#include <chrono>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

namespace ibmbrute_app {

int run_cli(int argc, char** argv) {
    try {
        std::vector<std::string> positional;
        Config cfg = parse_args(argc, argv, positional);

        if (cfg.help) {
            print_usage();
            return 0;
        }
        if (cfg.verify) {
            return verify_note_vectors() ? 0 : 1;
        }
        if (cfg.benchmark) {
            return run_cuda_benchmark(cfg);
        }
        if (cfg.attack_mode != 3) {
            throw std::runtime_error("only attack mode 3 is supported");
        }
        if (cfg.mode != "dst") {
            throw std::runtime_error("only -m dst is supported");
        }

        if (!cfg.restore_path.empty()) {
            const ResumeData restored = load_resume(cfg.restore_path);
            if (!restored.engine.empty()) cfg.engine = restored.engine;
            if (!restored.user.empty()) cfg.user = restored.user;
            if (!restored.target_hex.empty()) cfg.target_hex = restored.target_hex;
            if (!restored.hashfile_path.empty()) {
                if (!cfg.hashfile_path.empty() && cfg.hashfile_path != restored.hashfile_path) {
                    throw std::runtime_error("restore file hashfile does not match --hashfile");
                }
                cfg.hashfile_path = restored.hashfile_path;
            }
            cfg.charset = restored.charset.empty() ? cfg.charset : restored.charset;
            cfg.mask = restored.mask;
            cfg.custom1 = restored.custom1;
            cfg.custom2 = restored.custom2;
            cfg.custom3 = restored.custom3;
            cfg.custom4 = restored.custom4;
            cfg.min_len = restored.min_len;
            cfg.max_len = restored.max_len;
            cfg.compute = restored.compute;
        }

        if (cfg.compute) {
            if (!cfg.hashfile_path.empty()) {
                throw std::runtime_error("--compute is not compatible with --hashfile");
            }
            if (cfg.user.empty()) {
                throw std::runtime_error("missing --user");
            }
            if (cfg.password.empty()) {
                throw std::runtime_error("missing --password in --compute mode");
            }
            std::cout << dst::hex_encode(dst::hash_password(cfg.password, cfg.user)) << '\n';
            return 0;
        }

        const std::string requested_engine = cfg.engine;
        cfg.engine = resolve_engine(cfg);
        apply_cuda_launch_config(cfg);

        if (cfg.engine != "mt" && cfg.engine != "metal" && cfg.engine != "cuda") {
            throw std::runtime_error("unknown engine: " + cfg.engine);
        }
        if (cfg.engine == "metal" && !metal_backend::available()) {
            throw std::runtime_error("metal engine requested but Metal is not available at runtime: " +
                                     metal_backend::device_description());
        }
        if (cfg.engine == "cuda" && !cuda_backend::available()) {
            throw std::runtime_error("cuda engine requested but CUDA is not available at runtime: " +
                                     cuda_backend::device_description());
        }

        if (cfg.hashfile_path.empty() && cfg.target_hex.empty()) {
            if (positional.empty()) {
                throw std::runtime_error("missing target hash");
            }
            cfg.target_hex = positional.front();
        }
        if (!cfg.hashfile_path.empty() && !cfg.target_hex.empty()) {
            throw std::runtime_error("use either --hashfile or --target, not both");
        }

        const auto targets = load_targets(cfg);
        const std::string fingerprint = session_fingerprint(cfg);
        const std::string session_path = resolve_session_path(cfg);
        const auto plan = build_plan_from_config(cfg);
        const std::uint64_t per_target_total = total_candidates(plan);
        if (per_target_total == 0) {
            throw std::runtime_error("empty search space");
        }

        std::size_t start_target_index = 0;
        std::uint64_t start_position = 0;
        bool resumed_session = false;
        if (session_file_exists(session_path)) {
            const ResumeData restored = load_resume(session_path);
            if (session_should_resume(restored, cfg, fingerprint)) {
                if (restored.target_index < targets.size()) {
                    start_target_index = restored.target_index;
                    start_position = restored.position;
                    resumed_session = true;
                }
            } else if (!restored.complete && (cfg.session_explicit || cfg.restore_explicit)) {
                throw std::runtime_error("existing session file is incompatible with current input");
            }
        }

        if (start_target_index > targets.size()) {
            throw std::runtime_error("resume target index exceeds hashfile targets");
        }
        if (start_target_index == targets.size() && start_position != 0) {
            throw std::runtime_error("resume position exceeds hashfile targets");
        }

        std::size_t thread_count = 0;
        if (cfg.engine == "mt") {
            thread_count = resolve_thread_count(cfg);
            if (thread_count == 0) {
                throw std::runtime_error("thread count resolved to zero");
            }
        }

        const auto run_started = std::chrono::steady_clock::now();
        std::cerr << engine_banner(requested_engine, cfg, thread_count) << '\n';
        if (cfg.engine == "metal") {
            std::cerr << metal_banner() << '\n';
        } else if (cfg.engine == "cuda") {
            std::cerr << cuda_banner() << '\n';
        }

        std::uint64_t total_work = per_target_total;
        if (targets.size() > 1) {
            if (per_target_total > std::numeric_limits<std::uint64_t>::max() / targets.size()) {
                throw std::runtime_error("search space overflow");
            }
            total_work = per_target_total * static_cast<std::uint64_t>(targets.size());
        }

        if (resumed_session) {
            std::cerr << "resuming session: " << session_path
                      << " target=" << (start_target_index + 1) << '/' << targets.size()
                      << " position=" << start_position << '\n';
        }

        bool any_cracked = false;
        std::size_t total_matches = 0;
        save_session_state(session_path,
                           cfg,
                           fingerprint,
                           start_target_index,
                           start_position,
                           false,
                           targets[start_target_index < targets.size() ? start_target_index : targets.size() - 1].user,
                           targets[start_target_index < targets.size() ? start_target_index : targets.size() - 1].target_hex);

        for (std::size_t target_index = start_target_index; target_index < targets.size(); ++target_index) {
            const auto& target = targets[target_index];
            const std::uint64_t target_start = (target_index == start_target_index) ? start_position : 0;

            if (has_default_password(target)) {
                any_cracked = true;
                ++total_matches;
                std::cout << target.user << ':' << target.user << " -> " << target.target_hex << '\n';
                save_session_state(session_path,
                                   cfg,
                                   fingerprint,
                                   target_index + 1,
                                   0,
                                   target_index + 1 >= targets.size(),
                                   target.user,
                                   target.target_hex);
                continue;
            }

            CrackOutcome current_outcome;
            if (cfg.engine == "metal") {
                current_outcome = crack_target_metal(target,
                                                     plan,
                                                     cfg,
                                                     fingerprint,
                                                     session_path,
                                                     target_index,
                                                     targets.size(),
                                                     target_start,
                                                     per_target_total);
            } else if (cfg.engine == "cuda") {
                current_outcome = crack_target_cuda(target,
                                                    plan,
                                                    cfg,
                                                    fingerprint,
                                                    session_path,
                                                    target_index,
                                                    targets.size(),
                                                    target_start,
                                                    per_target_total);
            } else {
                current_outcome = crack_target(target,
                                               plan,
                                               cfg,
                                               fingerprint,
                                               session_path,
                                               target_index,
                                               targets.size(),
                                               target_start,
                                               per_target_total,
                                               thread_count);
            }

            if (current_outcome.interrupted) {
                const double elapsed =
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - run_started).count();
                std::cerr << "interrupted after " << format_duration(elapsed) << '\n'
                          << "\ninterrupted, session saved if configured\n";
                return 130;
            }

            if (current_outcome.found) {
                any_cracked = true;
                total_matches += current_outcome.passwords.size();
                if (!cfg.keep_going) {
                    for (const auto& password : current_outcome.passwords) {
                        std::cout << target.user << ':' << password << " -> " << target.target_hex << '\n';
                    }
                }
            } else {
                std::cout << target.user << ':' << target.target_hex << " -> not found\n";
            }
        }

        const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - run_started).count();
        const double average_rate = total_work / std::max(elapsed, 0.001);
        std::cerr << "finished in " << format_duration(elapsed) << " (" << format_rate(average_rate)
                  << " c/s average";
        if (total_matches > 0) {
            std::cerr << ", " << total_matches << " match" << (total_matches == 1 ? "" : "es");
        }
        std::cerr << ")\n";

        if (!any_cracked) {
            std::cout << "no match in " << format_number(total_work) << " candidates\n";
            return 1;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
}

}  // namespace ibmbrute_app
