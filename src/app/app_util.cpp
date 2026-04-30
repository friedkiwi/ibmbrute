#include "app.hpp"

#include "../cuda/cuda_backend.hpp"
#include "../metal/metal_backend.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <thread>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

namespace ibmbrute_app {

namespace {

std::uint64_t pow_u64(std::uint64_t base, std::size_t exp) {
    std::uint64_t out = 1;
    for (std::size_t i = 0; i < exp; ++i) {
        if (base != 0 && out > std::numeric_limits<std::uint64_t>::max() / base) {
            throw std::runtime_error("search space overflow");
        }
        out *= base;
    }
    return out;
}

std::string builtin_charset(std::string_view name) {
    if (name == "full") {
        return "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#@$_";
    }
    if (name == "ibm") {
        return "ABDFHJKMOQSUWY02468#@$_";
    }
    return std::string(name);
}

std::vector<Pattern> build_plan_from_lengths(const std::string& charset, std::size_t min_len, std::size_t max_len) {
    if (min_len == 0 || max_len == 0 || min_len > max_len) {
        throw std::runtime_error("invalid length range");
    }
    std::vector<Pattern> plan;
    const std::uint64_t radix = static_cast<std::uint64_t>(charset.size());
    for (std::size_t len = min_len; len <= max_len; ++len) {
        Pattern pattern;
        pattern.charsets.assign(len, charset);
        pattern.total = pow_u64(radix, len);
        plan.push_back(std::move(pattern));
    }
    return plan;
}

std::vector<Pattern> build_plan_from_mask(const std::string& mask,
                                          const std::string& c1,
                                          const std::string& c2,
                                          const std::string& c3,
                                          const std::string& c4) {
    if (mask.empty()) {
        throw std::runtime_error("mask cannot be empty");
    }

    std::vector<std::string> sets;
    sets.reserve(mask.size());
    for (std::size_t i = 0; i < mask.size(); ++i) {
        if (mask[i] != '?') {
            sets.emplace_back(1, mask[i]);
            continue;
        }
        if (i + 1 >= mask.size()) {
            throw std::runtime_error("dangling ? in mask");
        }
        const char token = mask[++i];
        switch (token) {
            case '1': sets.push_back(c1.empty() ? std::string("A") : c1); break;
            case '2': sets.push_back(c2.empty() ? std::string("A") : c2); break;
            case '3': sets.push_back(c3.empty() ? std::string("A") : c3); break;
            case '4': sets.push_back(c4.empty() ? std::string("A") : c4); break;
            default:
                throw std::runtime_error(std::string("unsupported mask token ?") + token);
        }
    }

    Pattern pattern;
    pattern.charsets = std::move(sets);
    pattern.total = 1;
    for (const auto& set : pattern.charsets) {
        if (set.empty()) {
            throw std::runtime_error("empty charset in mask");
        }
        if (pattern.total > std::numeric_limits<std::uint64_t>::max() / set.size()) {
            throw std::runtime_error("search space overflow");
        }
        pattern.total *= set.size();
    }
    return {std::move(pattern)};
}

bool is_hex_string(std::string_view s) {
    if (s.size() != 16) {
        return false;
    }
    return std::all_of(s.begin(), s.end(), [](unsigned char ch) { return std::isxdigit(ch) != 0; });
}

TargetEntry parse_hash_line(const std::string& raw_line, const std::string& fallback_user, std::size_t line_no) {
    const std::string line = trim(raw_line);
    if (line.empty() || line[0] == '#') {
        throw std::runtime_error("blank or comment line cannot be parsed as a hash");
    }

    const auto sep = line.rfind(':');
    if (sep == std::string::npos) {
        if (fallback_user.empty()) {
            throw std::runtime_error("hashfile line " + std::to_string(line_no) +
                                     " requires a user or a global --user");
        }
        return {fallback_user, line, dst::hex_decode8(line)};
    }

    const std::string left = trim(line.substr(0, sep));
    const std::string right = trim(line.substr(sep + 1));
    const bool left_is_hash = is_hex_string(left);
    const bool right_is_hash = is_hex_string(right);

    if (right_is_hash && !left.empty()) {
        return {left, right, dst::hex_decode8(right)};
    }
    if (left_is_hash && !right.empty()) {
        return {right, left, dst::hex_decode8(left)};
    }

    throw std::runtime_error("hashfile line " + std::to_string(line_no) + " must be HASH or USER:HASH");
}

std::size_t detect_cpu_cores() {
#if defined(__APPLE__)
    unsigned int count = 0;
    std::size_t len = sizeof(count);
    if (sysctlbyname("hw.activecpu", &count, &len, nullptr, 0) == 0 && count > 0) {
        return static_cast<std::size_t>(count);
    }
    len = sizeof(count);
    if (sysctlbyname("hw.logicalcpu", &count, &len, nullptr, 0) == 0 && count > 0) {
        return static_cast<std::size_t>(count);
    }
#elif defined(__linux__)
    const long count = sysconf(_SC_NPROCESSORS_ONLN);
    if (count > 0) {
        return static_cast<std::size_t>(count);
    }
#endif
    const unsigned int fallback = std::thread::hardware_concurrency();
    return fallback == 0 ? 1U : static_cast<std::size_t>(fallback);
}

}  // namespace

std::string trim(std::string s) {
    const auto not_space = [](unsigned char ch) { return std::isspace(ch) == 0; };
    while (!s.empty() && !not_space(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && !not_space(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

std::string Pattern::candidate(std::uint64_t index) const {
    std::string out;
    out.resize(charsets.size());
    for (std::ptrdiff_t pos = static_cast<std::ptrdiff_t>(charsets.size()) - 1; pos >= 0; --pos) {
        const auto& charset = charsets[static_cast<std::size_t>(pos)];
        const std::size_t radix = charset.size();
        if (radix == 0) {
            throw std::runtime_error("empty charset in pattern");
        }
        const std::size_t digit = static_cast<std::size_t>(index % radix);
        index /= radix;
        out[static_cast<std::size_t>(pos)] = charset[digit];
    }
    return out;
}

std::string format_number(std::uint64_t value) {
    std::string s = std::to_string(value);
    for (std::ptrdiff_t i = static_cast<std::ptrdiff_t>(s.size()) - 3; i > 0; i -= 3) {
        s.insert(static_cast<std::size_t>(i), ",");
    }
    return s;
}

std::string format_rate(double value) {
    const char* suffix = "";
    if (value >= 1e9) {
        value /= 1e9;
        suffix = "g";
    } else if (value >= 1e6) {
        value /= 1e6;
        suffix = "m";
    } else if (value >= 1e3) {
        value /= 1e3;
        suffix = "k";
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(3) << value << suffix;
    return oss.str();
}

std::string format_duration(double seconds) {
    if (seconds < 0) seconds = 0;
    const auto total = static_cast<std::uint64_t>(seconds + 0.5);
    const std::uint64_t h = total / 3600;
    const std::uint64_t m = (total % 3600) / 60;
    const std::uint64_t s = total % 60;
    std::ostringstream oss;
    oss << h << ':'
        << std::setw(2) << std::setfill('0') << m << ':'
        << std::setw(2) << std::setfill('0') << s;
    return oss.str();
}

void print_usage() {
    std::cout <<
R"(ibmbrute - brute-force DST/AS400 password hashes

Usage:
  ibmbrute --verify
  ibmbrute --benchmark
  ibmbrute --compute --user USER --password PASS
  ibmbrute --user USER --target HASH [options]

Options:
  -u, --user USER            User-id used as the DES plaintext
  -t, --target HASH          16 hex chars target hash
      --compute              Print the hash for --user/--password
      --benchmark            Run a synthetic CUDA benchmark and suggest
                             --cuda-batch-size / --cuda-thread-count
      --password PASS        Password to hash in --compute mode
      --hashfile FILE        Read HASH or USER:HASH lines from FILE
      --mt N                 Number of cracking threads; default is CPU cores
      --engine NAME         Cracking engine: mt, cuda, metal, or auto
      --cuda-batch-size N   CUDA candidates processed per batch
      --cuda-thread-count N CUDA threads per block; multiple of 32
      --charset NAME|TEXT    Charset for length-based brute force
                             Built-ins:
                               full (default) - all 40 DST-valid chars,
                                 recovers literal plaintext, 23^8 / 40^8
                                 = ~1/80 the rate of the canonical search
                               ibm            - 23-char DES-distinct subset,
                                 ~80x faster but returns canonical equivalent
                                 (only safe on V4R5 where parity is stripped)
      --mask MASK            Hashcat-style mask with ?1.. ?4 placeholders
  -1, -2, -3, -4 TEXT        Charsets used by mask placeholders
      --min-length N         Minimum length when no mask is supplied
      --max-length N         Maximum length when no mask is supplied
      --session FILE         Save resume state to FILE
                             Auto-generated if omitted
      --restore FILE         Resume from FILE and save back to it
                             if --session is not set
      --status / --no-status Enable or disable progress display
      --status-interval N    Progress update interval in seconds
      --keep-going           Continue scanning after a match to find all matches
  -a 3                       Only attack mode supported
  -m dst                     Only hash mode supported
  -h, --help                 Show this help
)";
}

Config parse_args(int argc, char** argv, std::vector<std::string>& positional) {
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto need_value = [&](const char* opt) -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error(std::string("missing value for ") + opt);
            }
            return argv[++i];
        };

        if (arg == "-h" || arg == "--help") {
            cfg.help = true;
        } else if (arg == "--verify") {
            cfg.verify = true;
        } else if (arg == "--benchmark") {
            cfg.benchmark = true;
        } else if (arg == "--compute") {
            cfg.compute = true;
        } else if (arg == "--status") {
            cfg.status = true;
        } else if (arg == "--no-status") {
            cfg.status = false;
        } else if (arg == "-u" || arg == "--user") {
            cfg.user = need_value(arg.c_str());
        } else if (arg == "-t" || arg == "--target") {
            cfg.target_hex = need_value(arg.c_str());
        } else if (arg == "--password") {
            cfg.password = need_value(arg.c_str());
        } else if (arg == "--hashfile" || arg == "--hash-file") {
            cfg.hashfile_path = need_value(arg.c_str());
        } else if (arg == "--mt") {
            cfg.mt_threads = static_cast<std::size_t>(std::stoull(need_value(arg.c_str())));
            cfg.mt_explicit = true;
        } else if (arg == "--engine") {
            cfg.engine = need_value(arg.c_str());
        } else if (arg == "--cuda-batch-size") {
            cfg.cuda_batch_size = static_cast<std::size_t>(std::stoull(need_value(arg.c_str())));
        } else if (arg == "--cuda-thread-count") {
            cfg.cuda_thread_count = static_cast<unsigned int>(std::stoul(need_value(arg.c_str())));
        } else if (arg == "--charset") {
            cfg.charset = need_value(arg.c_str());
        } else if (arg == "--mask") {
            cfg.mask = need_value(arg.c_str());
        } else if (arg == "-1") {
            cfg.custom1 = need_value(arg.c_str());
        } else if (arg == "-2") {
            cfg.custom2 = need_value(arg.c_str());
        } else if (arg == "-3") {
            cfg.custom3 = need_value(arg.c_str());
        } else if (arg == "-4") {
            cfg.custom4 = need_value(arg.c_str());
        } else if (arg == "--session") {
            cfg.session_path = need_value(arg.c_str());
            cfg.session_explicit = true;
        } else if (arg == "--restore") {
            cfg.restore_path = need_value(arg.c_str());
            cfg.restore_explicit = true;
        } else if (arg == "--min-length") {
            cfg.min_len = static_cast<std::size_t>(std::stoull(need_value(arg.c_str())));
        } else if (arg == "--max-length") {
            cfg.max_len = static_cast<std::size_t>(std::stoull(need_value(arg.c_str())));
        } else if (arg == "--status-interval") {
            cfg.status_interval = static_cast<std::size_t>(std::stoull(need_value(arg.c_str())));
        } else if (arg == "--keep-going") {
            cfg.keep_going = true;
        } else if (arg == "-a") {
            cfg.attack_mode = std::stoi(need_value(arg.c_str()));
        } else if (arg == "-m") {
            cfg.mode = need_value(arg.c_str());
        } else if (!arg.empty() && arg[0] == '-') {
            throw std::runtime_error("unknown option: " + arg);
        } else {
            positional.push_back(arg);
        }
    }
    return cfg;
}

bool verify_note_vectors() {
    struct Vector {
        std::string password;
        std::string user;
        std::string expected;
    };

    const std::vector<Vector> symmetric_vectors = {
        {"11111111", "11111111", "5D1B8FAF7839494B"},
        {"22222222", "22222222", "1C0A9280EECF5D48"},
        {"QSRV",     "QSRV",     "DC3FD085A03F9D16"},
        {"QSECOFR",  "QSECOFR",  "909495FE947D2D7E"},
    };
    const std::vector<Vector> asymmetric_vectors = {
        {"ABC",      "QSECOFR",  "D6809A2DF4A8EBC5"},
        {"PASSWORD", "QSECOFR",  "787715032A6E97BF"},
        {"HELLO",    "QSRV",     "0674F69C0E19144E"},
        {"AB",       "11111111", "4719F5B35DF10E9A"},
        {"X",        "QSECOFR",  "12B7CF46E893820A"},
    };

    bool ok = true;
    for (const auto& v : symmetric_vectors) {
        const auto actual = dst::hex_encode(dst::hash_password(v.password, v.user));
        if (actual != v.expected) {
            ok = false;
            std::cerr << "symmetric mismatch: " << v.password << '/' << v.user
                      << " expected " << v.expected << " got " << actual << '\n';
        } else {
            std::cout << "symmetric  " << v.user << ':' << v.password << " -> " << actual << '\n';
        }
    }
    for (const auto& v : asymmetric_vectors) {
        const auto actual = dst::hex_encode(dst::hash_password(v.password, v.user));
        if (actual != v.expected) {
            ok = false;
            std::cerr << "asymmetric mismatch: " << v.password << '/' << v.user
                      << " expected " << v.expected << " got " << actual << '\n';
        } else {
            std::cout << "asymmetric " << v.user << ':' << v.password << " -> " << actual << '\n';
        }
    }

    const auto qsecofr = dst::hex_encode(dst::hash_password("QSECOFR", "QSECOFR"));
    const auto qsdbofq = dst::hex_encode(dst::hash_password("QSDBOFQ", "QSECOFR"));
    if (qsecofr == qsdbofq) {
        ok = false;
        std::cerr << "parity check (password side) FAILED: 'QSECOFR' and 'QSDBOFQ' as passwords "
                     "for fixed user_id 'QSECOFR' produced the same hash (" << qsecofr << "). "
                     "This means hash_password() is using the OLD backwards orientation.\n";
    } else {
        std::cout << "parity check (password side OK): "
                  << "QSECOFR/QSECOFR=" << qsecofr << "  vs  QSDBOFQ/QSECOFR=" << qsdbofq << "\n";
    }

    const auto pwd_uid_qsecofr = dst::hex_encode(dst::hash_password("QSECOFR", "QSECOFR"));
    const auto pwd_uid_qsdbofq = dst::hex_encode(dst::hash_password("QSECOFR", "QSDBOFQ"));
    if (pwd_uid_qsecofr != pwd_uid_qsdbofq) {
        ok = false;
        std::cerr << "parity check (user_id side) FAILED: user_ids 'QSECOFR' and 'QSDBOFQ' should both produce "
                     "the same key after PC-1, but hashes differ ("
                  << pwd_uid_qsecofr << " vs " << pwd_uid_qsdbofq << ").\n";
    } else {
        std::cout << "parity check (user_id side OK): "
                  << "user_id 'QSECOFR' and 'QSDBOFQ' both yield " << pwd_uid_qsecofr << "\n";
    }
    return ok;
}

std::vector<TargetEntry> load_targets(const Config& cfg) {
    std::vector<TargetEntry> targets;
    if (!cfg.hashfile_path.empty()) {
        std::ifstream in(cfg.hashfile_path);
        if (!in) {
            throw std::runtime_error("failed to open hashfile: " + cfg.hashfile_path);
        }

        std::string line;
        std::size_t line_no = 0;
        while (std::getline(in, line)) {
            ++line_no;
            const std::string trimmed = trim(line);
            if (trimmed.empty() || trimmed[0] == '#') {
                continue;
            }
            targets.push_back(parse_hash_line(trimmed, cfg.user, line_no));
        }
        if (targets.empty()) {
            throw std::runtime_error("hashfile contained no targets");
        }
        return targets;
    }

    if (cfg.target_hex.empty()) {
        throw std::runtime_error("missing target hash");
    }
    if (cfg.user.empty()) {
        throw std::runtime_error("missing --user");
    }
    targets.push_back({cfg.user, cfg.target_hex, dst::hex_decode8(cfg.target_hex)});
    return targets;
}

std::size_t resolve_thread_count(const Config& cfg) {
    if (cfg.mt_explicit) {
        if (cfg.mt_threads == 0) {
            throw std::runtime_error("--mt must be greater than zero");
        }
        return cfg.mt_threads;
    }
    return detect_cpu_cores();
}

std::string engine_banner(std::string_view requested_engine, const Config& cfg, std::size_t thread_count) {
    std::ostringstream oss;
    if (cfg.engine == "metal") {
        oss << "engine: metal (" << (requested_engine == "auto" ? "auto-selected" : "selected by CLI")
            << ", batch size " << metal_backend::batch_size() << ")";
    } else if (cfg.engine == "cuda") {
        oss << "engine: cuda (" << (requested_engine == "auto" ? "auto-selected" : "selected by CLI")
            << ", batch size " << cuda_backend::batch_size() << ")";
    } else if (thread_count == 1) {
        oss << "engine: single-threaded CPU cracker (1 thread)";
    } else if (cfg.mt_explicit) {
        oss << "engine: multithreaded CPU cracker (selected by CLI, " << thread_count << " threads)";
    } else if (requested_engine == "auto") {
        oss << "engine: multithreaded CPU cracker (auto-selected fallback, spawned " << thread_count << " threads)";
    } else {
        oss << "engine: multithreaded CPU cracker (selected by CLI, spawned " << thread_count << " threads)";
    }
    return oss.str();
}

std::string metal_banner() {
    return std::string("metal: ") + metal_backend::device_description();
}

std::string cuda_banner() {
    return std::string("cuda: ") + cuda_backend::device_description();
}

void apply_cuda_launch_config(const Config& cfg) {
    if (cfg.cuda_batch_size == 0 && cfg.cuda_thread_count == 0) {
        return;
    }

    const std::size_t batch = cfg.cuda_batch_size == 0 ? cuda_backend::batch_size() : cfg.cuda_batch_size;
    const unsigned int threads = cfg.cuda_thread_count == 0 ? cuda_backend::thread_count() : cfg.cuda_thread_count;
    cuda_backend::set_launch_config(batch, threads);
}

std::string resolve_engine(const Config& cfg) {
    if (cfg.engine == "auto") {
        if (metal_backend::available()) {
            return "metal";
        }
        if (cuda_backend::available()) {
            return "cuda";
        }
        return "mt";
    }
    return cfg.engine;
}

int run_cuda_benchmark(const Config& cfg) {
    if (!cuda_backend::compiled()) {
        throw std::runtime_error("CUDA benchmark requested but CUDA support is not compiled in");
    }
    if (!cuda_backend::available()) {
        throw std::runtime_error("CUDA benchmark requested but CUDA is not available at runtime: " +
                                 cuda_backend::device_description());
    }

    apply_cuda_launch_config(cfg);
    const cuda_backend::BenchmarkResult result = cuda_backend::benchmark();
    if (result.batch_size == 0 || result.thread_count == 0) {
        std::cout << "cuda benchmark:\n"
                  << "  no viable launch configurations were found on this GPU\n";
        return 1;
    }

    std::cout << "cuda benchmark:\n"
              << "  batch size: " << result.batch_size << '\n'
              << "  thread count: " << result.thread_count << '\n'
              << "  throughput: " << format_rate(result.candidates_per_second) << " c/s\n"
              << "  suggested command: ibmbrute --engine cuda --cuda-batch-size " << result.batch_size
              << " --cuda-thread-count " << result.thread_count << " --user USER --target HASH [options]\n";
    return 0;
}

std::vector<Pattern> build_plan_from_config(const Config& cfg) {
    if (!cfg.mask.empty()) {
        return build_plan_from_mask(cfg.mask, cfg.custom1, cfg.custom2, cfg.custom3, cfg.custom4);
    }
    return build_plan_from_lengths(builtin_charset(cfg.charset), cfg.min_len, cfg.max_len);
}

std::uint64_t total_candidates(const std::vector<Pattern>& plan) {
    std::uint64_t total = 0;
    for (const auto& pattern : plan) {
        if (total > std::numeric_limits<std::uint64_t>::max() - pattern.total) {
            throw std::runtime_error("search space overflow");
        }
        total += pattern.total;
    }
    return total;
}

std::string candidate_for_index(const std::vector<Pattern>& plan, std::uint64_t index) {
    for (const auto& pattern : plan) {
        if (index < pattern.total) {
            return pattern.candidate(index);
        }
        index -= pattern.total;
    }
    throw std::runtime_error("candidate index out of range");
}

}  // namespace ibmbrute_app
