#include "dst_hash.hpp"
#include "metal/metal_backend.hpp"

#include <atomic>
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
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

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
    if (name == "full") {
        // Full 40-char DST alphabet: A-Z plus 0-9 plus the four EBCDIC-mappable
        // symbols (#, @, $, _) that the SST/DST password validator accepts.
        // Recovers the operator's literal plaintext.
        return "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#@$_";
    }
    if (name == "ibm") {
        // 23-char DES-distinct canonical alphabet: one ASCII rep per cp037
        // EBCDIC LSB-pair class, plus the 6 singletons (A J # @ $ _).
        // 17 LSB-pair reps (alphabetically-first of each pair) + 6 singletons
        // = 23 distinct DES-effective key bytes per position.  Search space
        // is 23^8 instead of 40^8 (80x smaller, ~80x faster), but the recovered
        // plaintext is the canonical equivalent of the operator's password,
        // not the original (e.g. "QSECOFR" recovers as "QSDBOFQ" because Q/R,
        // E/D, C/B all collide under DES key-schedule parity stripping).
        // This is the default. Useful for V4R5 hashes where any
        // equivalence-class member authenticates.  Not useful for V3R2, which
        // appears parity-sensitive.
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
      --mt N                 Number of cracking threads; default is CPU cores
      --engine NAME         Cracking engine: mt, metal, or auto
      --charset NAME|TEXT    Charset for length-based brute force
                             Built-ins:
                               full           - all 40 DST-valid chars,
                                 recovers literal plaintext, 23^8 / 40^8
                                 = ~1/80 the rate of the canonical search
                               ibm (default)  - 23-char DES-distinct subset,
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

ResumeData to_resume(const Config& cfg, const std::string& fingerprint, std::uint64_t position);
void save_session_state(const std::string& path,
                        const Config& cfg,
                        const std::string& fingerprint,
                        std::size_t target_index,
                        std::uint64_t position,
                        bool complete,
                        const std::string& user = std::string(),
                        const std::string& target_hex = std::string());

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
         << "engine=" << cfg.engine << '\n'
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

// Single integer overload covers both size_t and uint64_t.  Previously two
// overloads with the same body were defined, which collides on platforms
// where std::size_t and std::uint64_t are the same underlying type (Linux
// x86_64 gcc).  std::ostream's built-in formatter handles both numeric
// types via implicit conversion; output is identical.
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
    write_kv(out, "engine", data.engine);
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
    data.engine = get("engine");
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
        } else if (arg == "--mt") {
            cfg.mt_threads = static_cast<std::size_t>(std::stoull(need_value(arg.c_str())));
            cfg.mt_explicit = true;
        } else if (arg == "--engine") {
            cfg.engine = need_value(arg.c_str());
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

    // (1) Symmetric IBM-default vectors recovered from on-disk dumps in
    //     findings.md.  These pass under EITHER orientation of the formula,
    //     so they're necessary but not sufficient.
    const std::vector<Vector> symmetric_vectors = {
        {"11111111", "11111111", "5D1B8FAF7839494B"},
        {"22222222", "22222222", "1C0A9280EECF5D48"},
        {"QSRV",     "QSRV",     "DC3FD085A03F9D16"},
        {"QSECOFR",  "QSECOFR",  "909495FE947D2D7E"},
    };

    // (2) Asymmetric vectors computed offline against the corrected formula
    //     hash = DES(key=ebcdic8(user_id), plaintext=ebcdic8(password)).
    //     These DO disambiguate the orientation: the prior backwards
    //     hash_password() would not match any of these.
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

    // (3) Parity behaviour under the corrected formula:
    //     - LSB-equivalent passwords MUST produce DIFFERENT hashes (the password is
    //       the DES plaintext, no PC-1, every bit significant).
    //     - LSB-equivalent user-ids MUST produce IDENTICAL hashes (the user-id is
    //       the DES key, PC-1 strips LSBs).
    {
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
    }
    {
        const auto pwd_uid_qsecofr = dst::hex_encode(dst::hash_password("QSECOFR", "QSECOFR"));
        const auto pwd_uid_qsdbofq = dst::hex_encode(dst::hash_password("QSECOFR", "QSDBOFQ"));
        if (pwd_uid_qsecofr != pwd_uid_qsdbofq) {
            ok = false;
            std::cerr << "parity check (user_id side) FAILED: user_ids 'QSECOFR' and 'QSDBOFQ' "
                         "should both produce the same key after PC-1, but hashes differ ("
                      << pwd_uid_qsecofr << " vs " << pwd_uid_qsdbofq << ").\n";
        } else {
            std::cout << "parity check (user_id side OK): "
                      << "user_id 'QSECOFR' and 'QSDBOFQ' both yield " << pwd_uid_qsecofr << "\n";
        }
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
        oss << "engine: metal ("
            << (requested_engine == "auto" ? "auto-selected" : "selected by CLI")
            << ", batch size " << metal_backend::batch_size() << ")";
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

std::string resolve_engine(const Config& cfg) {
    if (cfg.engine == "auto") {
        return metal_backend::available() ? std::string("metal") : std::string("mt");
    }
    return cfg.engine;
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

struct CrackOutcome {
    bool found = false;
    bool interrupted = false;
    std::vector<std::string> passwords;
    std::uint64_t checkpoint = 0;
};

void emit_match_line(const std::string& user, const std::string& password, const std::string& target_hex) {
    static std::mutex output_mutex;
    std::lock_guard<std::mutex> lock(output_mutex);
    std::cout << user << ':' << password << " -> " << target_hex << '\n' << std::flush;
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
        if (checkpoint > total_work) {
            checkpoint = total_work;
        }
        return checkpoint;
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
                      << " current=";
            if (checkpoint < total_work) {
                std::cerr << candidate_for_index(plan, checkpoint);
            } else {
                std::cerr << "done";
            }
            std::cerr << std::flush;
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
                      << " current=";
            if (checkpoint < total_work) {
                std::cerr << candidate_for_index(plan, checkpoint);
            } else {
                std::cerr << "done";
            }
            std::cerr << std::flush;
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
                        const std::string& user,
                        const std::string& target_hex) {
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
    data.engine = cfg.engine;
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
            if (!restored.engine.empty()) {
                cfg.engine = restored.engine;
            }
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

        const std::string requested_engine = cfg.engine;
        const std::string resolved_engine = resolve_engine(cfg);
        cfg.engine = resolved_engine;

        if (cfg.engine != "mt" && cfg.engine != "metal") {
            throw std::runtime_error("unknown engine: " + cfg.engine);
        }
        if (cfg.engine == "metal" && !metal_backend::available()) {
            throw std::runtime_error("metal engine requested but Metal is not available at runtime: " +
                                     metal_backend::device_description());
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
                const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - run_started).count();
                std::cerr << "interrupted after " << format_duration(elapsed) << '\n';
                std::cerr << "\ninterrupted, session saved if configured\n";
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
        std::cerr << "finished in " << format_duration(elapsed)
                  << " (" << format_rate(average_rate) << " c/s average";
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
