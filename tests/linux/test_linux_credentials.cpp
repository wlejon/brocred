#include "check.h"
#include "brocred/storage.h"

#include <filesystem>
#include <unistd.h>

using namespace brocred;

// Round-trips through the default store. With a Secret Service daemon that is
// the user's real keyring, so the item is removed before and after (RAII, so
// also when a REQUIRE bails out). Without one the default is the file
// keystore under the user's data directory; the test then points it at a
// private temporary file instead of creating files in $HOME.
namespace {

struct TempDir {
    std::string path;
    TempDir() {
        char tmpl[] = "/tmp/brocred_linux_cred_XXXXXX";
        if (char* d = mkdtemp(tmpl)) path = d;
    }
    ~TempDir() {
        std::error_code ec;
        if (!path.empty()) std::filesystem::remove_all(path, ec);
    }
};

struct ScopedCleanup {
    CredentialStore* store;
    std::string service;
    std::string account;
    ScopedCleanup(CredentialStore* s, std::string svc, std::string acc)
        : store(s), service(std::move(svc)), account(std::move(acc)) {
        store->delete_secret(service, account);
    }
    ~ScopedCleanup() { store->delete_secret(service, account); }
};

}  // namespace

static void test_linux_cred_crud() {
    const std::string test_svc = "brocred_linux_test_svc";
    const std::string test_acc = "test_user_linux";

    TempDir tmp;
    REQUIRE(!tmp.path.empty());
    StorageOptions opts;
    opts.custom_file_path = tmp.path + "/credentials.store";
    auto store = CredentialStore::create(opts);
    REQUIRE(store != nullptr);
    std::printf("backend: %s\n", store->backend_name().c_str());
    ScopedCleanup guard(store.get(), test_svc, test_acc);

    std::map<std::string, std::string> attrs = {{"arch", "x86_64"}, {"distro", "arch"}};
    Result res = store->store_secret(test_svc, test_acc, "linux_pass_1234", attrs);
    CHECK(res.ok);

    auto sec = store->read_secret(test_svc, test_acc);
    REQUIRE(sec.has_value());
    CHECK_EQ(*sec, std::string("linux_pass_1234"));

    auto cred = store->read_credential(test_svc, test_acc);
    REQUIRE(cred.has_value());
    CHECK_EQ(cred->service, test_svc);
    CHECK_EQ(cred->account, test_acc);
    CHECK_EQ(cred->secret, std::string("linux_pass_1234"));
    CHECK(cred->attributes.count("distro") == 1 && cred->attributes.at("distro") == "arch");

    auto list = store->list_credentials(test_svc);
    CHECK_EQ(list.size(), size_t(1));

    Result del = store->delete_secret(test_svc, test_acc);
    CHECK(del.ok);

    CHECK(!store->read_secret(test_svc, test_acc).has_value());
}

int main() {
    test_linux_cred_crud();
    return bstest::finish("test_linux_credentials");
}
