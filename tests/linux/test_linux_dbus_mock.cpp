#include "check.h"
#include "linux/dbus/dbus_bus.h"

#include <fcntl.h>
#include <systemd/sd-bus.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace brocred::linux_dbus;

// Starts a private dbus-daemon in an isolated temporary directory
class PrivateBus {
public:
    PrivateBus() {
        char dir_template[] = "/tmp/brocred_bus_XXXXXX";
        char* tmp = mkdtemp(dir_template);
        if (!tmp) return;
        dir_ = tmp;
        socket_path_ = dir_ + "/bus";
        config_path_ = dir_ + "/bus.conf";

        std::string xml =
            "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n"
            " \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n"
            "<busconfig>\n"
            "  <type>session</type>\n"
            "  <listen>unix:path=" + socket_path_ + "</listen>\n"
            "  <auth>EXTERNAL</auth>\n"
            "  <policy context=\"default\">\n"
            "    <allow send_destination=\"*\" eavesdrop=\"true\"/>\n"
            "    <allow eavesdrop=\"true\"/>\n"
            "    <allow own=\"*\"/>\n"
            "  </policy>\n"
            "</busconfig>\n";

        std::ofstream conf(config_path_);
        conf << xml;
        conf.close();

        int pipefd[2];
        if (pipe(pipefd) != 0) return;

        pid_t pid = fork();
        if (pid == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[1]);

            int devnull = open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                dup2(devnull, STDIN_FILENO);
                dup2(devnull, STDERR_FILENO);
                if (devnull > 2) close(devnull);
            }

            execlp("dbus-daemon", "dbus-daemon",
                   ("--config-file=" + config_path_).c_str(),
                   "--nofork", "--nopidfile", "--print-address=1", nullptr);
            _exit(127);
        }

        close(pipefd[1]);
        pid_ = pid;

        char buf[256];
        ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
        close(pipefd[0]);
        if (n > 0) {
            buf[n] = '\0';
            std::string line = buf;
            size_t nl = line.find('\n');
            if (nl != std::string::npos) line = line.substr(0, nl);
            address_ = line;
        }
    }

    ~PrivateBus() {
        if (pid_ > 0) {
            kill(pid_, SIGKILL);
            waitpid(pid_, nullptr, 0);
        }
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
    }

    bool ok() const { return !address_.empty() && pid_ > 0; }
    const std::string& address() const { return address_; }

private:
    std::string dir_;
    std::string socket_path_;
    std::string config_path_;
    std::string address_;
    pid_t pid_ = -1;
};

// Vtable callbacks for Secret Service mock
static int handle_open_session(sd_bus_message* m, void* /*userdata*/, sd_bus_error* /*ret_error*/) {
    return sd_bus_reply_method_return(m, "vo", "s", "", "/org/freedesktop/secrets/session/s1");
}

static int handle_search_items(sd_bus_message* m, void* /*userdata*/, sd_bus_error* /*ret_error*/) {
    return sd_bus_reply_method_return(m, "aoao", 1, "/org/freedesktop/secrets/collection/default/item1", 0);
}

static int handle_create_item(sd_bus_message* m, void* /*userdata*/, sd_bus_error* /*ret_error*/) {
    return sd_bus_reply_method_return(m, "oo", "/org/freedesktop/secrets/collection/default/item1", "/");
}

static int handle_get_secret(sd_bus_message* m, void* /*userdata*/, sd_bus_error* /*ret_error*/) {
    const char secret_text[] = "mock_secret_payload_42";
    sd_bus_message* reply = nullptr;
    int r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;

    r = sd_bus_message_open_container(reply, 'r', "oayays");
    if (r >= 0) {
        sd_bus_message_append(reply, "o", "/org/freedesktop/secrets/session/s1");
        sd_bus_message_append_array(reply, 'y', nullptr, 0);
        sd_bus_message_append_array(reply, 'y', secret_text, std::strlen(secret_text));
        sd_bus_message_append(reply, "s", "text/plain");
        sd_bus_message_close_container(reply);
    }
    r = sd_bus_send(nullptr, reply, nullptr);
    sd_bus_message_unref(reply);
    return r;
}

static int handle_delete_item(sd_bus_message* m, void* /*userdata*/, sd_bus_error* /*ret_error*/) {
    return sd_bus_reply_method_return(m, "o", "/");
}

static int handle_fprint_get_devices(sd_bus_message* m, void* /*userdata*/, sd_bus_error* /*ret_error*/) {
    return sd_bus_reply_method_return(m, "ao", 1, "/net/reactivated/Fprint/Device/0");
}

static int handle_fprint_list_enrolled(sd_bus_message* m, void* /*userdata*/, sd_bus_error* /*ret_error*/) {
    return sd_bus_reply_method_return(m, "as", 1, "right-index-finger");
}

static const sd_bus_vtable kSecretServiceVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("OpenSession", "sv", "vo", handle_open_session, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("SearchItems", "a{ss}", "aoao", handle_search_items, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable kCollectionVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("CreateItem", "a{sv}(oayays)b", "oo", handle_create_item, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable kItemVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("GetSecret", "o", "(oayays)", handle_get_secret, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Delete", "", "o", handle_delete_item, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable kFprintManagerVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("GetDevices", "", "ao", handle_fprint_get_devices, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable kFprintDeviceVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("ListEnrolledFingers", "s", "as", handle_fprint_list_enrolled, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

static void test_mock_secret_service_and_fprint() {
    PrivateBus bus;
    if (!bus.ok()) {
        bstest::skip("test_linux_dbus_mock", "Failed to start private dbus-daemon");
    }

    // Set up mock server on the private bus
    sd_bus* server_bus = nullptr;
    int r = sd_bus_new(&server_bus);
    REQUIRE(r >= 0 && server_bus != nullptr);
    sd_bus_set_address(server_bus, bus.address().c_str());
    sd_bus_set_bus_client(server_bus, 1);
    r = sd_bus_start(server_bus);
    REQUIRE(r >= 0);

    // Request names
    r = sd_bus_request_name(server_bus, "org.freedesktop.secrets", 0);
    CHECK(r >= 0);
    r = sd_bus_request_name(server_bus, "net.reactivated.Fprint", 0);
    CHECK(r >= 0);

    // Register objects
    sd_bus_add_object_vtable(server_bus, nullptr,
                             "/org/freedesktop/secrets",
                             "org.freedesktop.Secret.Service",
                             kSecretServiceVtable, nullptr);

    sd_bus_add_object_vtable(server_bus, nullptr,
                             "/org/freedesktop/secrets/aliases/default",
                             "org.freedesktop.Secret.Collection",
                             kCollectionVtable, nullptr);

    sd_bus_add_object_vtable(server_bus, nullptr,
                             "/org/freedesktop/secrets/collection/default/item1",
                             "org.freedesktop.Secret.Item",
                             kItemVtable, nullptr);

    sd_bus_add_object_vtable(server_bus, nullptr,
                             "/net/reactivated/Fprint/Manager",
                             "net.reactivated.Fprint.Manager",
                             kFprintManagerVtable, nullptr);

    sd_bus_add_object_vtable(server_bus, nullptr,
                             "/net/reactivated/Fprint/Device/0",
                             "net.reactivated.Fprint.Device",
                             kFprintDeviceVtable, nullptr);

    struct ServerRunner {
        std::atomic<bool> running{true};
        std::thread thread;
        sd_bus* bus = nullptr;

        ~ServerRunner() {
            running = false;
            if (bus) sd_bus_close(bus);
            if (thread.joinable()) thread.join();
            if (bus) sd_bus_flush_close_unref(bus);
        }
    } server_runner;
    server_runner.bus = server_bus;
    server_runner.thread = std::thread([server_bus, &server_runner] {
        while (server_runner.running) {
            sd_bus_process(server_bus, nullptr);
            sd_bus_wait(server_bus, 20000);
        }
    });

    // Client connects to the mock server over private bus
    auto client = BusConnection::open(BusType::Address, bus.address());
    REQUIRE(client != nullptr && client->valid());

    CHECK(client->has_owner("org.freedesktop.secrets"));
    CHECK(client->has_owner("net.reactivated.Fprint"));

    // 1. OpenSession
    std::string session_path;
    std::string err;
    bool ok = client->secret_service_open_session(session_path, &err);
    CHECK(ok);
    CHECK_EQ(session_path, std::string("/org/freedesktop/secrets/session/s1"));

    // 2. CreateItem
    std::string created_item;
    std::map<std::string, std::string> attrs = {{"service", "testsvc"}, {"account", "testuser"}};
    ok = client->secret_service_create_item("", session_path, "Test Label", attrs,
                                            "secret_data", true, created_item, &err);
    CHECK(ok);
    CHECK_EQ(created_item, std::string("/org/freedesktop/secrets/collection/default/item1"));

    // 3. SearchItems
    std::vector<std::string> unlocked, locked;
    ok = client->secret_service_search_items(attrs, unlocked, locked, &err);
    CHECK(ok);
    REQUIRE(!unlocked.empty());
    CHECK_EQ(unlocked[0], std::string("/org/freedesktop/secrets/collection/default/item1"));

    // 4. GetSecret
    std::string secret_val;
    ok = client->secret_service_get_secret(unlocked[0], session_path, secret_val, &err);
    CHECK(ok);
    CHECK_EQ(secret_val, std::string("mock_secret_payload_42"));

    // 5. Delete
    ok = client->secret_service_delete_item(unlocked[0], &err);
    CHECK(ok);

    // 6. fprintd GetDevices
    std::vector<std::string> devices;
    ok = client->fprint_get_devices(devices, &err);
    CHECK(ok);
    REQUIRE(!devices.empty());
    CHECK_EQ(devices[0], std::string("/net/reactivated/Fprint/Device/0"));

    // 7. fprintd ListEnrolledFingers
    std::vector<std::string> fingers;
    ok = client->fprint_list_enrolled_fingers(devices[0], "testuser", fingers, &err);
    CHECK(ok);
    REQUIRE(!fingers.empty());
    CHECK_EQ(fingers[0], std::string("right-index-finger"));
}

int main() {
    test_mock_secret_service_and_fprint();
    return bstest::finish("test_linux_dbus_mock");
}
