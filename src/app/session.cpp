#include "app.hpp"

#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <vector>

namespace ibmbrute_app {

namespace {

std::uint64_t fnv1a64(const std::string& text, std::uint64_t seed = 1469598103934665603ull) {
    std::uint64_t hash = seed;
    for (std::size_t i = 0; i < text.size(); ++i) {
        hash ^= static_cast<unsigned char>(text[i]);
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
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return "missing";
    }

    return std::to_string(static_cast<unsigned long long>(info.st_size)) + ":" +
           std::to_string(static_cast<long long>(info.st_mtime));
}

std::string default_session_path(const Config& cfg) {
    return ".ibmbrute-" + session_fingerprint(cfg) + ".session";
}

std::string found_passwords_path() {
    return "ibmbrute-found.txt";
}

void write_kv(std::ostream& out, const char* key, const std::string& value) {
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

ResumeData to_resume(const Config& cfg, const std::string& fingerprint, std::uint64_t position) {
    ResumeData data;
    data.mode = cfg.mask.empty() ? "lengths" : "mask";
    data.engine = cfg.engine;
    data.user = cfg.user;
    data.target_hex = cfg.target_hex;
    data.hashfile_path = cfg.hashfile_path;
    data.fingerprint = fingerprint;
    data.charset = cfg.charset;
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

struct FoundPasswordRecord {
    std::string user;
    std::string target_hex;
    std::string password;
};

bool parse_found_password_line(const std::string& raw_line, FoundPasswordRecord* record) {
    const std::string line = trim(raw_line);
    if (line.empty() || line[0] == '#') {
        return false;
    }

    const auto first_sep = line.find(':');
    if (first_sep == std::string::npos) {
        return false;
    }
    const auto second_sep = line.find(':', first_sep + 1);
    if (second_sep == std::string::npos || line.find(':', second_sep + 1) != std::string::npos) {
        return false;
    }

    const std::string user = trim(line.substr(0, first_sep));
    const std::string target_hex = trim(line.substr(first_sep + 1, second_sep - first_sep - 1));
    const std::string password = trim(line.substr(second_sep + 1));
    if (user.empty() || target_hex.empty() || password.empty()) {
        return false;
    }

    record->user = user;
    record->target_hex = target_hex;
    record->password = password;
    return true;
}

bool found_record_matches_target(const FoundPasswordRecord& record, const TargetEntry& target) {
    if (record.user != target.user) {
        return false;
    }
    try {
        return dst::hex_decode8(record.target_hex) == target.target;
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<FoundPasswordRecord> load_found_password_records(const std::string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return {};
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open found-password file: " + path);
    }

    std::vector<FoundPasswordRecord> records;
    std::string line;
    while (std::getline(in, line)) {
        FoundPasswordRecord record;
        if (parse_found_password_line(line, &record)) {
            records.push_back(std::move(record));
        }
    }
    return records;
}

void write_found_password_records(const std::string& path, const std::vector<FoundPasswordRecord>& records) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("failed to write found-password file: " + path);
    }
    for (const auto& record : records) {
        out << record.user << ':' << record.target_hex << ':' << record.password << '\n';
    }
}

}  // namespace

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

bool session_file_exists(const std::string& path) {
    struct stat info;
    return stat(path.c_str(), &info) == 0;
}

bool session_should_resume(const ResumeData& resume, const Config& cfg, const std::string& fingerprint) {
    if (resume.complete) {
        return false;
    }
    if (!resume.fingerprint.empty() && resume.fingerprint != fingerprint) {
        return false;
    }
    if (!resume.hashfile_path.empty() && !cfg.hashfile_path.empty() && resume.hashfile_path != cfg.hashfile_path) {
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

bool password_matches_target(const TargetEntry& target, const std::string& password) {
    return dst::hash_password(password, target.user) == target.target;
}

bool load_found_password(const TargetEntry& target, std::string* password) {
    const std::vector<FoundPasswordRecord> records = load_found_password_records(found_passwords_path());
    for (const auto& record : records) {
        if (!found_record_matches_target(record, target)) {
            continue;
        }
        if (!password_matches_target(target, record.password)) {
            continue;
        }
        if (password != nullptr) {
            *password = record.password;
        }
        return true;
    }
    return false;
}

bool save_found_password(const TargetEntry& target, const std::string& password) {
    if (!password_matches_target(target, password)) {
        return false;
    }

    const std::string path = found_passwords_path();
    std::vector<FoundPasswordRecord> records = load_found_password_records(path);
    bool saw_target = false;
    bool mutated = false;
    for (auto& record : records) {
        if (!found_record_matches_target(record, target)) {
            continue;
        }
        saw_target = true;
        if (password_matches_target(target, record.password)) {
            return true;
        }
        record.password = password;
        record.target_hex = target.target_hex;
        mutated = true;
    }

    if (mutated) {
        write_found_password_records(path, records);
        return true;
    }

    if (saw_target) {
        return true;
    }

    std::ofstream out(path, std::ios::app | std::ios::binary);
    if (!out) {
        throw std::runtime_error("failed to write found-password file: " + path);
    }
    out << target.user << ':' << target.target_hex << ':' << password << '\n';
    return true;
}

}  // namespace ibmbrute_app
