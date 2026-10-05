// Private isolated dbus-daemon for real wire-protocol D-Bus tests.
#pragma once

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

namespace brocred::test {

class PrivateBus {
public:
    PrivateBus() {
        char dir_template[] = "/tmp/brocred_test_bus_XXXXXX";
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

}  // namespace brocred::test
