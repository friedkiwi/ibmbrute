#pragma once

#include "../dst_hash.hpp"

#include <csignal>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace ibmbrute_app {

extern volatile std::sig_atomic_t g_stop;

void on_signal(int);

std::string trim(std::string s);
std::string format_number(std::uint64_t value);
std::string format_rate(double value);
std::string format_duration(double seconds);

struct Pattern {
    std::vector<std::string> charsets;
    std::uint64_t total = 0;

    std::string candidate(std::uint64_t index) const;
};

struct Config {
    bool verify = false;
    bool compute = false;
    bool benchmark = false;
    bool help = false;
    bool status = true;
    bool keep_going = false;
    bool session_explicit = false;
    bool restore_explicit = false;
    int attack_mode = 3;
    bool mt_explicit = false;
    std::size_t mt_threads = 0;
    std::string engine = "auto";
    std::string mode = "dst";
    std::string user;
    std::string target_hex;
    std::string password;
    std::string session_path;
    std::string restore_path;
    std::string hashfile_path;
    std::string charset = "full";
    std::string mask;
    std::string custom1;
    std::string custom2;
    std::string custom3;
    std::string custom4;
    std::size_t min_len = 1;
    std::size_t max_len = 8;
    std::size_t status_interval = 1;
    std::size_t cuda_batch_size = 0;
    unsigned int cuda_thread_count = 0;
};

struct ResumeData {
    std::string mode;
    std::string user;
    std::string target_hex;
    std::string hashfile_path;
    std::string fingerprint;
    std::string engine;
    std::string charset;
    std::string mask;
    std::string custom1;
    std::string custom2;
    std::string custom3;
    std::string custom4;
    std::size_t min_len = 0;
    std::size_t max_len = 0;
    std::size_t target_index = 0;
    std::uint64_t position = 0;
    bool complete = false;
    bool compute = false;
};

struct TargetEntry {
    std::string user;
    std::string target_hex;
    dst::Block8 target;
};

struct CrackOutcome {
    bool found = false;
    bool interrupted = false;
    std::vector<std::string> passwords;
    std::uint64_t checkpoint = 0;
};

using ProgressCallback = std::function<void(std::uint64_t processed, std::uint64_t total_work)>;

void print_usage();
Config parse_args(int argc, char** argv, std::vector<std::string>& positional);
bool verify_note_vectors();
std::vector<TargetEntry> load_targets(const Config& cfg);
std::size_t resolve_thread_count(const Config& cfg);
std::string engine_banner(std::string_view requested_engine, const Config& cfg, std::size_t thread_count);
std::string metal_banner();
std::string cuda_banner();
void apply_cuda_launch_config(const Config& cfg);
std::string resolve_engine(const Config& cfg);
int run_cuda_benchmark(const Config& cfg);

std::vector<Pattern> build_plan_from_config(const Config& cfg);
std::uint64_t total_candidates(const std::vector<Pattern>& plan);
std::string candidate_for_index(const std::vector<Pattern>& plan, std::uint64_t index);

ResumeData load_resume(const std::string& path);
std::string session_fingerprint(const Config& cfg);
bool session_file_exists(const std::string& path);
bool session_should_resume(const ResumeData& resume, const Config& cfg, const std::string& fingerprint);
std::string resolve_session_path(Config& cfg);
void save_session_state(const std::string& path,
                        const Config& cfg,
                        const std::string& fingerprint,
                        std::size_t target_index,
                        std::uint64_t position,
                        bool complete,
                        const std::string& user = std::string(),
                        const std::string& target_hex = std::string());

CrackOutcome crack_target(const TargetEntry& target,
                          const std::vector<Pattern>& plan,
                          const Config& cfg,
                          const std::string& fingerprint,
                          const std::string& session_path,
                          std::size_t target_index,
                          std::size_t target_count,
                          std::uint64_t start_position,
                          std::uint64_t total_work,
                          std::size_t thread_count);
CrackOutcome crack_target_metal(const TargetEntry& target,
                                const std::vector<Pattern>& plan,
                                const Config& cfg,
                                const std::string& fingerprint,
                                const std::string& session_path,
                                std::size_t target_index,
                                std::size_t target_count,
                                std::uint64_t start_position,
                                std::uint64_t total_work);
CrackOutcome crack_target_cuda(const TargetEntry& target,
                               const std::vector<Pattern>& plan,
                               const Config& cfg,
                               const std::string& fingerprint,
                               const std::string& session_path,
                               std::size_t target_index,
                               std::size_t target_count,
                               std::uint64_t start_position,
                               std::uint64_t total_work,
                               const ProgressCallback& progress_callback = ProgressCallback());

int run_cli(int argc, char** argv);

}  // namespace ibmbrute_app
