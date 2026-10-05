// Implementation of PolicyKit types and D-Bus serialization helpers.
#include "linux/polkit/polkit_types.h"

#include <grp.h>
#include <pwd.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace brocred {

PolkitSubject PolkitSubject::current_process() {
    uint32_t pid = static_cast<uint32_t>(getpid());
    uint64_t start_time = polkit::read_process_start_time(pid);
    return process(pid, start_time);
}

PolkitSubject PolkitSubject::process(uint32_t pid, uint64_t start_time) {
    PolkitSubject s;
    s.kind = Kind::UnixProcess;
    s.pid = pid;
    s.start_time = start_time;
    return s;
}

PolkitSubject PolkitSubject::session(std::string session_id) {
    PolkitSubject s;
    s.kind = Kind::UnixSession;
    s.session_id = std::move(session_id);
    return s;
}

PolkitIdentity PolkitIdentity::user(uint32_t uid, std::string name) {
    PolkitIdentity id;
    id.kind = Kind::UnixUser;
    id.id = uid;
    if (name.empty()) {
        struct passwd* pw = getpwuid(uid);
        if (pw && pw->pw_name) id.name = pw->pw_name;
    } else {
        id.name = std::move(name);
    }
    return id;
}

PolkitIdentity PolkitIdentity::group(uint32_t gid, std::string name) {
    PolkitIdentity id;
    id.kind = Kind::UnixGroup;
    id.id = gid;
    if (name.empty()) {
        struct group* gr = getgrgid(gid);
        if (gr && gr->gr_name) id.name = gr->gr_name;
    } else {
        id.name = std::move(name);
    }
    return id;
}

PolkitIdentity PolkitIdentity::current_user() {
    return user(static_cast<uint32_t>(getuid()));
}

}  // namespace brocred

namespace brocred::polkit {

uint64_t read_process_start_time(uint32_t pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream f(path);
    if (!f.is_open()) return 0;

    std::string line;
    if (!std::getline(f, line)) return 0;

    // Process name is inside parentheses. Find the last ')'
    size_t closing = line.rfind(')');
    if (closing == std::string::npos || closing + 2 >= line.size()) return 0;

    // Remaining string starts with field 3 (state)
    std::istringstream iss(line.substr(closing + 2));
    std::string val;
    // Field 22 (starttime) is the 20th field after closing ')'
    for (int i = 0; i < 19; ++i) {
        if (!(iss >> val)) return 0;
    }

    uint64_t start_time = 0;
    if (iss >> start_time) {
        return start_time;
    }
    return 0;
}

int append_subject(sd_bus_message* m, const PolkitSubject& subject) {
    // Subject struct: (sa{sv})
    int r = sd_bus_message_open_container(m, 'r', "sa{sv}");
    if (r < 0) return r;

    if (subject.kind == PolkitSubject::Kind::UnixProcess) {
        r = sd_bus_message_append(m, "s", "unix-process");
        if (r < 0) return r;
        r = sd_bus_message_open_container(m, 'a', "{sv}");
        if (r < 0) return r;

        // pid: uint32
        r = sd_bus_message_open_container(m, 'e', "sv");
        if (r >= 0) {
            sd_bus_message_append(m, "s", "pid");
            sd_bus_message_open_container(m, 'v', "u");
            sd_bus_message_append(m, "u", subject.pid);
            sd_bus_message_close_container(m);
            sd_bus_message_close_container(m);
        }

        // start-time: uint64
        r = sd_bus_message_open_container(m, 'e', "sv");
        if (r >= 0) {
            sd_bus_message_append(m, "s", "start-time");
            sd_bus_message_open_container(m, 'v', "t");
            sd_bus_message_append(m, "t", subject.start_time);
            sd_bus_message_close_container(m);
            sd_bus_message_close_container(m);
        }

        sd_bus_message_close_container(m); // a{sv}
    } else {
        r = sd_bus_message_append(m, "s", "unix-session");
        if (r < 0) return r;
        r = sd_bus_message_open_container(m, 'a', "{sv}");
        if (r < 0) return r;

        r = sd_bus_message_open_container(m, 'e', "sv");
        if (r >= 0) {
            sd_bus_message_append(m, "s", "session-id");
            sd_bus_message_open_container(m, 'v', "s");
            sd_bus_message_append(m, "s", subject.session_id.c_str());
            sd_bus_message_close_container(m);
            sd_bus_message_close_container(m);
        }

        sd_bus_message_close_container(m); // a{sv}
    }

    return sd_bus_message_close_container(m); // r
}

int read_subject(sd_bus_message* m, PolkitSubject& subject) {
    int r = sd_bus_message_enter_container(m, 'r', "sa{sv}");
    if (r <= 0) return r;

    const char* kind = nullptr;
    r = sd_bus_message_read(m, "s", &kind);
    if (r < 0 || !kind) {
        sd_bus_message_exit_container(m);
        return r < 0 ? r : -EINVAL;
    }

    if (std::strcmp(kind, "unix-process") == 0) {
        subject.kind = PolkitSubject::Kind::UnixProcess;
    } else if (std::strcmp(kind, "unix-session") == 0) {
        subject.kind = PolkitSubject::Kind::UnixSession;
    }

    r = sd_bus_message_enter_container(m, 'a', "{sv}");
    if (r >= 0) {
        while ((r = sd_bus_message_enter_container(m, 'e', "sv")) > 0) {
            const char* key = nullptr;
            sd_bus_message_read(m, "s", &key);
            if (key && std::strcmp(key, "pid") == 0) {
                sd_bus_message_enter_container(m, 'v', "u");
                sd_bus_message_read(m, "u", &subject.pid);
                sd_bus_message_exit_container(m);
            } else if (key && std::strcmp(key, "start-time") == 0) {
                sd_bus_message_enter_container(m, 'v', "t");
                sd_bus_message_read(m, "t", &subject.start_time);
                sd_bus_message_exit_container(m);
            } else if (key && std::strcmp(key, "session-id") == 0) {
                const char* sid = nullptr;
                sd_bus_message_enter_container(m, 'v', "s");
                sd_bus_message_read(m, "s", &sid);
                if (sid) subject.session_id = sid;
                sd_bus_message_exit_container(m);
            } else {
                sd_bus_message_skip(m, "v");
            }
            sd_bus_message_exit_container(m); // e
        }
        sd_bus_message_exit_container(m); // a{sv}
    }

    return sd_bus_message_exit_container(m); // r
}

int append_identity(sd_bus_message* m, const PolkitIdentity& identity) {
    // Identity struct: (sa{sv})
    int r = sd_bus_message_open_container(m, 'r', "sa{sv}");
    if (r < 0) return r;

    if (identity.kind == PolkitIdentity::Kind::UnixUser) {
        r = sd_bus_message_append(m, "s", "unix-user");
        if (r < 0) return r;
        r = sd_bus_message_open_container(m, 'a', "{sv}");
        if (r < 0) return r;

        r = sd_bus_message_open_container(m, 'e', "sv");
        if (r >= 0) {
            sd_bus_message_append(m, "s", "uid");
            sd_bus_message_open_container(m, 'v', "u");
            sd_bus_message_append(m, "u", identity.id);
            sd_bus_message_close_container(m);
            sd_bus_message_close_container(m);
        }
        sd_bus_message_close_container(m);
    } else {
        r = sd_bus_message_append(m, "s", "unix-group");
        if (r < 0) return r;
        r = sd_bus_message_open_container(m, 'a', "{sv}");
        if (r < 0) return r;

        r = sd_bus_message_open_container(m, 'e', "sv");
        if (r >= 0) {
            sd_bus_message_append(m, "s", "gid");
            sd_bus_message_open_container(m, 'v', "u");
            sd_bus_message_append(m, "u", identity.id);
            sd_bus_message_close_container(m);
            sd_bus_message_close_container(m);
        }
        sd_bus_message_close_container(m);
    }

    return sd_bus_message_close_container(m);
}

int read_identity(sd_bus_message* m, PolkitIdentity& identity) {
    int r = sd_bus_message_enter_container(m, 'r', "sa{sv}");
    if (r <= 0) return r;

    const char* kind = nullptr;
    r = sd_bus_message_read(m, "s", &kind);
    if (r < 0 || !kind) {
        sd_bus_message_exit_container(m);
        return r < 0 ? r : -EINVAL;
    }

    if (std::strcmp(kind, "unix-user") == 0) {
        identity.kind = PolkitIdentity::Kind::UnixUser;
    } else if (std::strcmp(kind, "unix-group") == 0) {
        identity.kind = PolkitIdentity::Kind::UnixGroup;
    }

    r = sd_bus_message_enter_container(m, 'a', "{sv}");
    if (r >= 0) {
        while ((r = sd_bus_message_enter_container(m, 'e', "sv")) > 0) {
            const char* key = nullptr;
            sd_bus_message_read(m, "s", &key);
            if (key && (std::strcmp(key, "uid") == 0 || std::strcmp(key, "gid") == 0)) {
                sd_bus_message_enter_container(m, 'v', "u");
                sd_bus_message_read(m, "u", &identity.id);
                sd_bus_message_exit_container(m);
            } else {
                sd_bus_message_skip(m, "v");
            }
            sd_bus_message_exit_container(m);
        }
        sd_bus_message_exit_container(m);
    }

    // Resolve name
    if (identity.kind == PolkitIdentity::Kind::UnixUser) {
        struct passwd* pw = getpwuid(identity.id);
        if (pw && pw->pw_name) identity.name = pw->pw_name;
    } else {
        struct group* gr = getgrgid(identity.id);
        if (gr && gr->gr_name) identity.name = gr->gr_name;
    }

    return sd_bus_message_exit_container(m);
}

int append_identities(sd_bus_message* m, const std::vector<PolkitIdentity>& identities) {
    int r = sd_bus_message_open_container(m, 'a', "(sa{sv})");
    if (r < 0) return r;

    for (const auto& id : identities) {
        r = append_identity(m, id);
        if (r < 0) return r;
    }

    return sd_bus_message_close_container(m);
}

int read_identities(sd_bus_message* m, std::vector<PolkitIdentity>& identities) {
    identities.clear();
    int r = sd_bus_message_enter_container(m, 'a', "(sa{sv})");
    if (r < 0) return r;

    while (true) {
        PolkitIdentity id;
        r = read_identity(m, id);
        if (r <= 0) break;
        identities.push_back(std::move(id));
    }

    if (r < 0) {
        sd_bus_message_exit_container(m);
        return r;
    }

    return sd_bus_message_exit_container(m);
}

int append_details(sd_bus_message* m, const std::map<std::string, std::string>& details) {
    int r = sd_bus_message_open_container(m, 'a', "{ss}");
    if (r < 0) return r;

    for (const auto& [k, v] : details) {
        r = sd_bus_message_append(m, "{ss}", k.c_str(), v.c_str());
        if (r < 0) return r;
    }

    return sd_bus_message_close_container(m);
}

int read_details(sd_bus_message* m, std::map<std::string, std::string>& details) {
    details.clear();
    int r = sd_bus_message_enter_container(m, 'a', "{ss}");
    if (r < 0) return r;

    while ((r = sd_bus_message_enter_container(m, 'e', "ss")) > 0) {
        const char *k = nullptr, *v = nullptr;
        sd_bus_message_read(m, "ss", &k, &v);
        if (k && v) details[k] = v;
        sd_bus_message_exit_container(m);
    }

    return sd_bus_message_exit_container(m);
}

}  // namespace brocred::polkit
