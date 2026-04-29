#include "dst_hash.hpp"

#include <algorithm>
#include <csignal>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
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
    bool session_explicit = false;
    bool restore_explicit = false;
    int attack_mode = 3;
    std::string mode = "dst";
    std::string user;
    std::string target_hex;
    std::string password;
    std::string session_path;
    std::string restore_path;
    std::string hashfile_path;
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
      --hashfile FILE        Read HASH or USER:HASH lines from FILE
      --charset NAME|TEXT    Charset for length-based brute force
                             Built-ins: ibm, full
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
  -a 3                       Only attack mode supported
  -m dst                     Only hash mode supported
  -h, --help                 Show this help
)";
}

struct ResumeData {
    std::string mode;
    std::string user;
    std::string target_hex;
    std::string hashfile_path;
    std::string fingerprint;
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

ResumeData to_resume(const Config& cfg, const std::string& fingerprint, std::uint64_t position);

std::uint64_t fnv1a64(std::string_view text, std::uint64_t seed = 1469598103934665603ull) {
    std::uint64_t hash = seed;
    for (unsigned char ch : text) {
        hash ^= ch;
        hash *= 1099511628211ull;
    }
    return hash;
}

std::string hex_u64(std::uint64_t value) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = digits[value & 0x0f];
        value >>= 4;
    }
    return out;
}

std::string file_signature(const std::string& path) {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(path, ec)) {
        return "missing";
    }

    const auto size = fs::file_size(path, ec);
    const auto stamp = fs::last_write_time(path, ec);
    const auto stamp_count = ec ? 0 : stamp.time_since_epoch().count();
    return std::to_string(static_cast<unsigned long long>(size)) + ":" +
           std::to_string(static_cast<long long>(stamp_count));
}

std::string session_fingerprint(const Config& cfg) {
    std::ostringstream seed;
    seed << "mode=" << cfg.mode << '\n'
         << "user=" << cfg.user << '\n'
         << "target=" << cfg.target_hex << '\n'
         << "hashfile=" << cfg.hashfile_path << '\n'
         << "hashfile_sig=" << file_signature(cfg.hashfile_path) << '\n'
         << "charset=" << cfg.charset << '\n'
         << "mask=" << cfg.mask << '\n'
         << "c1=" << cfg.custom1 << '\n'
         << "c2=" << cfg.custom2 << '\n'
         << "c3=" << cfg.custom3 << '\n'
         << "c4=" << cfg.custom4 << '\n'
         << "min_len=" << cfg.min_len << '\n'
         << "max_len=" << cfg.max_len << '\n'
         << "attack=" << cfg.attack_mode;
    return hex_u64(fnv1a64(seed.str()));
}

std::string default_session_path(const Config& cfg) {
    return ".ibmbrute-" + session_fingerprint(cfg) + ".session";
}

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
    write_kv(out, "hashfile", data.hashfile_path);
    write_kv(out, "fingerprint", data.fingerprint);
    write_kv(out, "charset", data.charset);
    write_kv(out, "mask", data.mask);
    write_kv(out, "custom1", data.custom1);
    write_kv(out, "custom2", data.custom2);
    write_kv(out, "custom3", data.custom3);
    write_kv(out, "custom4", data.custom4);
    write_kv(out, "min_len", data.min_len);
    write_kv(out, "max_len", data.max_len);
    write_kv(out, "target_index", data.target_index);
    write_kv(out, "position", data.position);
    write_kv(out, "complete", static_cast<std::size_t>(data.complete ? 1 : 0));
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
    data.hashfile_path = get("hashfile");
    data.fingerprint = get("fingerprint");
    data.charset = get("charset");
    data.mask = get("mask");
    data.custom1 = get("custom1");
    data.custom2 = get("custom2");
    data.custom3 = get("custom3");
    data.custom4 = get("custom4");
    data.min_len = static_cast<std::size_t>(std::stoull(get("min_len", "0")));
    data.max_len = static_cast<std::size_t>(std::stoull(get("max_len", "0")));
    data.target_index = static_cast<std::size_t>(std::stoull(get("target_index", "0")));
    data.position = std::stoull(get("position", "0"));
    data.complete = std::stoull(get("complete", "0")) != 0;
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
        } else if (arg == "--hashfile" || arg == "--hash-file") {
            cfg.hashfile_path = need_value(arg.c_str());
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

struct TargetEntry {
    std::string user;
    std::string target_hex;
    dst::Block8 target;
};

bool is_hex_string(std::string_view s) {
    if (s.size() != 16) {
        return false;
    }
    return std::all_of(s.begin(), s.end(), [](unsigned char ch) { return std::isxdigit(ch) != 0; });
}

TargetEntry parse_hash_line(const std::string& raw_line,
                            const std::string& fallback_user,
                            std::size_t line_no) {
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

    throw std::runtime_error("hashfile line " + std::to_string(line_no) +
                             " must be HASH or USER:HASH");
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

bool session_file_exists(const std::string& path) {
    namespace fs = std::filesystem;
    std::error_code ec;
    return fs::exists(path, ec);
}

bool session_should_resume(const ResumeData& resume,
                           const Config& cfg,
                           const std::string& fingerprint) {
    if (resume.complete) {
        return false;
    }
    if (!resume.fingerprint.empty() && resume.fingerprint != fingerprint) {
        return false;
    }
    if (!resume.hashfile_path.empty() && !cfg.hashfile_path.empty() &&
        resume.hashfile_path != cfg.hashfile_path) {
        return false;
    }
    if (!resume.target_hex.empty() && !cfg.target_hex.empty() && resume.target_hex != cfg.target_hex) {
        return false;
    }
    return true;
}

std::string resolve_session_path(Config& cfg) {
    if (cfg.session_path.empty()) {
        if (!cfg.restore_path.empty()) {
            cfg.session_path = cfg.restore_path;
        } else {
            cfg.session_path = default_session_path(cfg);
        }
    }
    return cfg.session_path;
}

void save_session_state(const std::string& path,
                        const Config& cfg,
                        const std::string& fingerprint,
                        std::size_t target_index,
                        std::uint64_t position,
                        bool complete,
                        const std::string& user = std::string(),
                        const std::string& target_hex = std::string()) {
    ResumeData data = to_resume(cfg, fingerprint, position);
    data.target_index = target_index;
    data.complete = complete;
    if (!user.empty()) {
        data.user = user;
    }
    if (!target_hex.empty()) {
        data.target_hex = target_hex;
    }
    save_resume(path, data);
}

std::vector<Pattern> build_plan_from_config(const Config& cfg) {
    if (!cfg.mask.empty()) {
        return build_plan_from_mask(cfg.mask, cfg.custom1, cfg.custom2, cfg.custom3, cfg.custom4);
    }
    return build_plan_from_lengths(builtin_charset(cfg.charset), cfg.min_len, cfg.max_len);
}

ResumeData to_resume(const Config& cfg, const std::string& fingerprint, std::uint64_t position) {
    ResumeData data;
    data.mode = cfg.mask.empty() ? "lengths" : "mask";
    data.user = cfg.user;
    data.target_hex = cfg.target_hex;
    data.hashfile_path = cfg.hashfile_path;
    data.fingerprint = fingerprint;
    data.charset = builtin_charset(cfg.charset);
    data.mask = cfg.mask;
    data.custom1 = cfg.custom1;
    data.custom2 = cfg.custom2;
    data.custom3 = cfg.custom3;
    data.custom4 = cfg.custom4;
    data.min_len = cfg.min_len;
    data.max_len = cfg.max_len;
    data.target_index = 0;
    data.position = position;
    data.complete = false;
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
            if (!restored.user.empty()) {
                cfg.user = restored.user;
            }
            if (!restored.target_hex.empty()) {
                cfg.target_hex = restored.target_hex;
            }
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
            const auto hash = dst::hex_encode(dst::hash_password(cfg.password, cfg.user));
            std::cout << hash << '\n';
            return 0;
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

        const std::string fingerprint = session_fingerprint(cfg);
        const std::string session_path = resolve_session_path(cfg);
        const auto plan = build_plan_from_config(cfg);
        const auto targets = load_targets(cfg);

        std::uint64_t per_target_total = 0;
        for (const auto& pattern : plan) {
            if (per_target_total > std::numeric_limits<std::uint64_t>::max() - pattern.total) {
                throw std::runtime_error("search space overflow");
            }
            per_target_total += pattern.total;
        }
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

        std::uint64_t total_work = per_target_total;
        if (targets.size() > 1) {
            if (per_target_total > std::numeric_limits<std::uint64_t>::max() / targets.size()) {
                throw std::runtime_error("search space overflow");
            }
            total_work = per_target_total * static_cast<std::uint64_t>(targets.size());
        }

        std::uint64_t processed = static_cast<std::uint64_t>(start_target_index) * per_target_total + start_position;
        auto started = std::chrono::steady_clock::now();
        auto last_status = started;
        auto last_save = started;
        bool any_cracked = false;

        if (resumed_session) {
            std::cerr << "resuming session: " << session_path
                      << " target=" << (start_target_index + 1) << '/' << targets.size()
                      << " position=" << start_position << '\n';
        }

        const TargetEntry* initial_target = targets.empty() ? nullptr : &targets[start_target_index < targets.size() ? start_target_index : targets.size() - 1];
        save_session_state(session_path,
                           cfg,
                           fingerprint,
                           start_target_index,
                           start_position,
                           false,
                           initial_target ? initial_target->user : std::string(),
                           initial_target ? initial_target->target_hex : std::string());

        for (std::size_t target_index = start_target_index; target_index < targets.size(); ++target_index) {
            const auto& target = targets[target_index];
            std::uint64_t global_position = 0;
            std::uint64_t local_position = (target_index == start_target_index) ? start_position : 0;
            while (!plan.empty() && local_position >= plan[0].total) {
                local_position -= plan[0].total;
                global_position += plan[0].total;
            }

            bool found = false;
            std::string found_password;

            for (std::size_t pattern_index = 0; pattern_index < plan.size(); ++pattern_index) {
                const auto& pattern = plan[pattern_index];
                const std::uint64_t begin = (pattern_index == 0) ? local_position : 0;
                local_position = 0;
                for (std::uint64_t idx = begin; idx < pattern.total; ++idx) {
                    if (g_stop) {
                        save_session_state(session_path,
                                           cfg,
                                           fingerprint,
                                           target_index,
                                           global_position + idx + 1,
                                           false,
                                           target.user,
                                           target.target_hex);
                        std::cerr << "\ninterrupted, session saved if configured\n";
                        return 130;
                    }

                    const std::string candidate = pattern.candidate(idx);
                    const auto actual = dst::hash_password(candidate, target.user);
                    ++processed;
                    if (actual == target.target) {
                        found = true;
                        found_password = candidate;
                        any_cracked = true;
                        std::cout << target.user << ':' << found_password << " -> " << target.target_hex << '\n';
                        save_session_state(session_path,
                                           cfg,
                                           fingerprint,
                                           target_index + 1,
                                           0,
                                           true,
                                           target.user,
                                           target.target_hex);
                        break;
                    }

                    const auto now = std::chrono::steady_clock::now();
                    const double elapsed = std::chrono::duration<double>(now - started).count();
                    const auto save_elapsed = std::chrono::duration<double>(now - last_save).count();
                    if (save_elapsed >= static_cast<double>(cfg.status_interval)) {
                        save_session_state(session_path,
                                           cfg,
                                           fingerprint,
                                           target_index,
                                           global_position + idx + 1,
                                           false,
                                           target.user,
                                           target.target_hex);
                        last_save = now;
                    }
                    if (cfg.status && elapsed >= static_cast<double>(cfg.status_interval) &&
                        now - last_status >= std::chrono::seconds(static_cast<int>(cfg.status_interval))) {
                        const double rate = processed / std::max(elapsed, 0.001);
                        const double remaining = total_work > processed ? static_cast<double>(total_work - processed) / rate : 0.0;
                        std::cerr << "\r"
                                  << "target " << (target_index + 1) << '/' << targets.size()
                                  << " " << target.user << ':' << target.target_hex
                                  << " progress " << format_number(processed) << '/' << format_number(total_work)
                                  << " (" << std::fixed << std::setprecision(2)
                                  << (100.0 * static_cast<double>(processed) / static_cast<double>(total_work)) << "%)"
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

            if (!found) {
                save_session_state(session_path,
                                   cfg,
                                   fingerprint,
                                   target_index + 1,
                                   0,
                                   false,
                                   target.user,
                                   target.target_hex);
            }
            if (cfg.status) {
                std::cerr << '\r' << std::string(140, ' ') << '\r';
            }

            if (!found) {
                std::cout << target.user << ':' << target.target_hex << " -> not found\n";
            }
        }

        save_session_state(session_path, cfg, fingerprint, targets.size(), 0, true);
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
