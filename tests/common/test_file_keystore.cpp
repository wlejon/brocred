#include "check.h"
#include "brocred/storage.h"
#include "common/file_keystore.h"

#include <filesystem>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

using namespace brocred;

struct TempTestFile {
    std::string path;
    TempTestFile(std::string p) : path(std::move(p)) {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
    ~TempTestFile() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
};

static void test_file_persistence_and_permissions() {
    std::filesystem::path tmp_dir = std::filesystem::temp_directory_path();
    std::string test_store_file = (tmp_dir / "brocred_test_store.dat").string();
    TempTestFile cleanup(test_store_file);

    StorageOptions opts;
    opts.backend = BackendType::FileKeystore;
    opts.custom_file_path = test_store_file;

    {
        auto store = CredentialStore::create(opts);
        REQUIRE(store != nullptr);
        CHECK_EQ(store->backend_name(), std::string("FileKeystore"));

        std::map<std::string, std::string> attrs = {{"api_version", "v2"}, {"tier", "gold"}};
        Result r = store->store_secret("com.brocred.test", "bob", "secret_pass_999", attrs);
        CHECK(r.ok);

        // Check file exists on disk
        std::error_code ec;
        CHECK(std::filesystem::exists(test_store_file, ec));

#if !defined(_WIN32)
        // Check file permissions are restricted to owner (0600)
        struct stat st{};
        if (stat(test_store_file.c_str(), &st) == 0) {
            mode_t mode = st.st_mode & 0777;
            CHECK_EQ(mode, mode_t(0600));
        }
#endif
    }

    // Open with a second instance and verify contents
    {
        auto store2 = CredentialStore::create(opts);
        REQUIRE(store2 != nullptr);

        auto sec = store2->read_secret("com.brocred.test", "bob");
        REQUIRE(sec.has_value());
        CHECK_EQ(*sec, std::string("secret_pass_999"));

        auto cred = store2->read_credential("com.brocred.test", "bob");
        REQUIRE(cred.has_value());
        CHECK_EQ(cred->service, std::string("com.brocred.test"));
        CHECK_EQ(cred->account, std::string("bob"));
        CHECK_EQ(cred->attributes.at("tier"), std::string("gold"));

        Result del = store2->delete_secret("com.brocred.test", "bob");
        CHECK(del.ok);
    }

    // Verify deletion persisted
    {
        auto store3 = CredentialStore::create(opts);
        REQUIRE(store3 != nullptr);
        CHECK(!store3->read_secret("com.brocred.test", "bob").has_value());
    }
}

int main() {
    test_file_persistence_and_permissions();
    return bstest::finish("test_file_keystore");
}
