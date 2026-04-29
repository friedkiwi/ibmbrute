#include "dst_hash.hpp"

#include <csignal>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

volatile std::sig_atomic_t g_stop = 0;

void on_signal(int) {
    g_stop = 1;
}

std::string trim(std::string s) {
    const auto not_space = [](unsigned char ch) { return std::isspace(ch) == 0; };
    while (!s.empty() && !not_space(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && !not_space(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

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

std::string format_number(std::uint64_t value) {
    std::string s = std::to_string(value);
    for (std::ptrdiff_t i = static_cast<std::ptrdiff_t>(s.size()) - 3; i > 0; i -= 3) {
        s.insert(static_cast<std::size_t>(i), ",");
    }
    return s;
}

std::string format_rate(double value) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(value >= 1000.0 ? 0 : 1) << value;
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

struct Pattern {
    std::vector<std::string> charsets;
    std::uint64_t total = 0;

    std::string candidate(std::uint64_t index) const {
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
};

struct Config {
    bool verify = false;
    bool compute = false;
    bool help = false;
    bool status = true;
    int attack_mode = 3;
    std::string mode = "dst";
    std::string user;
    std::string target_hex;
    std::string password;
    std::string session_path;
    std::string restore_path;
    std::string charset = "ibm";
    std::string mask;
    std::string custom1;
    std::string custom2;
    std::string custom3;
    std::string custom4;
    std::size_t min_len = 1;
    std::size_t max_len = 8;
    std::size_t status_interval = 1;
};

std::string builtin_charset(std::string_view name) {
    if (name == "ibm") {
        return "ABDFHKMOQSUWY02468AJ#@$_";
    }
    if (name == "full") {
        return "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#@$_";
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

void print_usage() {
    std::cout <<
R"(ibmbrute - brute-force DST/AS400 password hashes

Usage:
  ibmbrute --verify
  ibmbrute --compute --user USER --password PASS
  ibmbrute --user USER --target HASH [options]

Options:
  -u, --user USER            User-id used as the DES plaintext
  -t, --target HASH          16 hex chars target hash
      --compute              Print the hash for --user/--password
      --password PASS        Password to hash in --compute mode
      --charset NAME|TEXT    Charset for length-based brute force
                             Built-ins: ibm, full
      --mask MASK            Hashcat-style mask with ?1.. ?4 placeholders
  -1, -2, -3, -4 TEXT        Charsets used by mask placeholders
      --min-length N         Minimum length when no mask is supplied
      --max-length N         Maximum length when no mask is supplied
      --session FILE         Save resume state to FILE
      --restore FILE         Resume from FILE
      --status / --no-status Enable or disable progress display
      --status-interval N    Progress update interval in seconds
  -a 3                       Only attack mode supported
  -m dst                     Only hash mode supported
  -h, --help                 Show this help
)";
}

struct ResumeData {
    std::string mode;
    std::string user;
    std::string target_hex;
    std::string charset;
    std::string mask;
    std::string custom1;
    std::string custom2;
    std::string custom3;
    std::string custom4;
    std::size_t min_len = 0;
    std::size_t max_len = 0;
    std::uint64_t position = 0;
    bool compute = false;
};

void write_kv(std::ostream& out, const char* key, const std::string& value) {
    out << key << '=' << value << '\n';
}

void write_kv(std::ostream& out, const char* key, std::size_t value) {
    out << key << '=' << value << '\n';
}

void write_kv(std::ostream& out, const char* key, std::uint64_t value) {
    out << key << '=' << value << '\n';
}

void save_resume(const std::string& path, const ResumeData& data) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("failed to write session file: " + path);
    }
    out << "version=1\n";
    write_kv(out, "mode", data.mode);
    write_kv(out, "user", data.user);
    write_kv(out, "target", data.target_hex);
    write_kv(out, "charset", data.charset);
    write_kv(out, "mask", data.mask);
    write_kv(out, "custom1", data.custom1);
    write_kv(out, "custom2", data.custom2);
    write_kv(out, "custom3", data.custom3);
    write_kv(out, "custom4", data.custom4);
    write_kv(out, "min_len", data.min_len);
    write_kv(out, "max_len", data.max_len);
    write_kv(out, "position", data.position);
    write_kv(out, "compute", static_cast<std::size_t>(data.compute ? 1 : 0));
}

std::map<std::string, std::string> load_kv_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open session file: " + path);
    }
    std::map<std::string, std::string> kv;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        const auto pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        kv.emplace(trim(line.substr(0, pos)), trim(line.substr(pos + 1)));
    }
    return kv;
}

ResumeData load_resume(const std::string& path) {
    const auto kv = load_kv_file(path);
    ResumeData data;
    const auto get = [&](const char* key, const std::string& fallback = std::string()) -> std::string {
        const auto it = kv.find(key);
        return it == kv.end() ? fallback : it->second;
    };
    data.mode = get("mode");
    data.user = get("user");
    data.target_hex = get("target");
    data.charset = get("charset");
    data.mask = get("mask");
    data.custom1 = get("custom1");
    data.custom2 = get("custom2");
    data.custom3 = get("custom3");
    data.custom4 = get("custom4");
    data.min_len = static_cast<std::size_t>(std::stoull(get("min_len", "0")));
    data.max_len = static_cast<std::size_t>(std::stoull(get("max_len", "0")));
    data.position = std::stoull(get("position", "0"));
    data.compute = std::stoull(get("compute", "0")) != 0;
    return data;
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
        } else if (arg == "--restore") {
            cfg.restore_path = need_value(arg.c_str());
        } else if (arg == "--min-length") {
            cfg.min_len = static_cast<std::size_t>(std::stoull(need_value(arg.c_str())));
        } else if (arg == "--max-length") {
            cfg.max_len = static_cast<std::size_t>(std::stoull(need_value(arg.c_str())));
        } else if (arg == "--status-interval") {
            cfg.status_interval = static_cast<std::size_t>(std::stoull(need_value(arg.c_str())));
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
    const std::vector<Vector> vectors = {
        {"11111111", "11111111", "5D1B8FAF7839494B"},
        {"22222222", "22222222", "1C0A9280EECF5D48"},
        {"QSRV", "QSRV", "DC3FD085A03F9D16"},
        {"QSECOFR", "QSECOFR", "909495FE947D2D7E"},
    };
    bool ok = true;
    for (const auto& v : vectors) {
        const auto actual = dst::hex_encode(dst::hash_password(v.password, v.user));
        if (actual != v.expected) {
            ok = false;
            std::cerr << "mismatch: " << v.password << '/' << v.user
                      << " expected " << v.expected << " got " << actual << '\n';
        } else {
            std::cout << v.user << ':' << v.password << " -> " << actual << '\n';
        }
    }
    const auto qsrv = dst::hex_encode(dst::hash_password("QSRV", "QSRV"));
    const auto qsqu = dst::hex_encode(dst::hash_password("QSQU", "QSRV"));
    if (qsrv != qsqu) {
        ok = false;
        std::cerr << "equivalence check failed: QSRV and QSQU should collide, got "
                  << qsrv << " vs " << qsqu << '\n';
    } else {
        std::cout << "equivalence check: QSRV == QSQU -> " << qsrv << '\n';
    }
    return ok;
}

std::vector<Pattern> build_plan_from_config(const Config& cfg) {
    if (!cfg.mask.empty()) {
        return build_plan_from_mask(cfg.mask, cfg.custom1, cfg.custom2, cfg.custom3, cfg.custom4);
    }
    return build_plan_from_lengths(builtin_charset(cfg.charset), cfg.min_len, cfg.max_len);
}

ResumeData to_resume(const Config& cfg, std::uint64_t position) {
    ResumeData data;
    data.mode = cfg.mask.empty() ? "lengths" : "mask";
    data.user = cfg.user;
    data.target_hex = cfg.target_hex;
    data.charset = builtin_charset(cfg.charset);
    data.mask = cfg.mask;
    data.custom1 = cfg.custom1;
    data.custom2 = cfg.custom2;
    data.custom3 = cfg.custom3;
    data.custom4 = cfg.custom4;
    data.min_len = cfg.min_len;
    data.max_len = cfg.max_len;
    data.position = position;
    data.compute = cfg.compute;
    return data;
}

}  // namespace

int main(int argc, char** argv) {
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

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

        if (cfg.attack_mode != 3) {
            throw std::runtime_error("only attack mode 3 is supported");
        }
        if (cfg.mode != "dst") {
            throw std::runtime_error("only -m dst is supported");
        }

        if (!cfg.restore_path.empty()) {
            const ResumeData restored = load_resume(cfg.restore_path);
            cfg.user = restored.user;
            cfg.target_hex = restored.target_hex;
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

        if (cfg.user.empty()) {
            throw std::runtime_error("missing --user");
        }

        if (!cfg.compute) {
            if (cfg.target_hex.empty()) {
                if (positional.empty()) {
                    throw std::runtime_error("missing target hash");
                }
                cfg.target_hex = positional.front();
            }
            if (cfg.target_hex.empty()) {
                throw std::runtime_error("missing target hash");
            }
        }

        if (cfg.compute) {
            if (cfg.password.empty()) {
                throw std::runtime_error("missing --password in --compute mode");
            }
            const auto hash = dst::hex_encode(dst::hash_password(cfg.password, cfg.user));
            std::cout << hash << '\n';
            return 0;
        }

        const auto target = dst::hex_decode8(cfg.target_hex);
        const auto plan = build_plan_from_config(cfg);

        std::uint64_t total = 0;
        for (const auto& pattern : plan) {
            if (total > std::numeric_limits<std::uint64_t>::max() - pattern.total) {
                throw std::runtime_error("search space overflow");
            }
            total += pattern.total;
        }
        if (total == 0) {
            throw std::runtime_error("empty search space");
        }

        std::uint64_t start_position = 0;
        if (!cfg.restore_path.empty()) {
            const ResumeData restored = load_resume(cfg.restore_path);
            start_position = restored.position;
        }

        if (start_position >= total) {
            throw std::runtime_error("resume position exceeds search space");
        }

        std::uint64_t global_position = 0;
        std::uint64_t processed = start_position;
        auto started = std::chrono::steady_clock::now();
        auto last_status = started;
        bool found = false;
        std::string found_password;

        std::size_t pattern_index = 0;
        std::uint64_t local_position = start_position;
        while (pattern_index < plan.size() && local_position >= plan[pattern_index].total) {
            local_position -= plan[pattern_index].total;
            global_position += plan[pattern_index].total;
            ++pattern_index;
        }

        for (; pattern_index < plan.size(); ++pattern_index) {
            const auto& pattern = plan[pattern_index];
            const std::uint64_t begin = local_position;
            local_position = 0;
            for (std::uint64_t idx = begin; idx < pattern.total; ++idx) {
                if (g_stop) {
                    if (!cfg.session_path.empty()) {
                        save_resume(cfg.session_path, to_resume(cfg, global_position + idx + 1));
                    }
                    std::cerr << "\ninterrupted, session saved if configured\n";
                    return 130;
                }

                const std::string candidate = pattern.candidate(idx);
                const auto actual = dst::hash_password(candidate, cfg.user);
                ++processed;
                if (actual == target) {
                    found = true;
                    found_password = candidate;
                    if (!cfg.session_path.empty()) {
                        save_resume(cfg.session_path, to_resume(cfg, global_position + idx + 1));
                    }
                    break;
                }

                const auto now = std::chrono::steady_clock::now();
                const double elapsed = std::chrono::duration<double>(now - started).count();
                if (cfg.status && elapsed >= static_cast<double>(cfg.status_interval) &&
                    now - last_status >= std::chrono::seconds(static_cast<int>(cfg.status_interval))) {
                    const double rate = processed / std::max(elapsed, 0.001);
                    const double remaining = total > processed ? static_cast<double>(total - processed) / rate : 0.0;
                    std::cerr << "\r"
                              << "progress " << format_number(processed) << '/' << format_number(total)
                              << " (" << std::fixed << std::setprecision(2)
                              << (100.0 * static_cast<double>(processed) / static_cast<double>(total)) << "%)"
                              << " " << format_rate(rate) << " c/s"
                              << " eta " << format_duration(remaining)
                              << " current=" << candidate << std::flush;
                    last_status = now;
                }
            }
            global_position += pattern.total;
            if (found) {
                break;
            }
        }

        if (cfg.status) {
            std::cerr << '\r' << std::string(120, ' ') << '\r';
        }

        if (found) {
            std::cout << cfg.user << ':' << found_password << " -> " << cfg.target_hex << '\n';
            return 0;
        }

        if (!cfg.session_path.empty()) {
            save_resume(cfg.session_path, to_resume(cfg, total));
        }
        std::cout << "no match in " << format_number(total) << " candidates\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
}
