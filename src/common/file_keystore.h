// File-based credential store.
#pragma once

#include "common/memory_keystore.h"

#include <string>

namespace brocred {

class FileKeystore : public MemoryKeystore {
public:
    explicit FileKeystore(std::string file_path = "");
    ~FileKeystore() override = default;

    Result store_secret(const std::string& service, const std::string& account,
                        const std::string& secret) override;
    Result store_secret(const std::string& service, const std::string& account,
                        const std::string& secret,
                        const std::map<std::string, std::string>& attributes) override;

    Result delete_secret(const std::string& service, const std::string& account) override;

    std::string backend_name() const override { return "FileKeystore"; }
    const std::string& file_path() const { return file_path_; }

    static std::string default_keystore_path();

private:
    bool load_from_disk();
    bool save_to_disk();

    std::string file_path_;
};

}  // namespace brocred
