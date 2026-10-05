// Factory methods for SecretServiceProvider.
#include "brocred/secret_service.h"
#include "linux/secret_service/secret_service_impl.h"

namespace brocred {

std::unique_ptr<SecretServiceProvider> SecretServiceProvider::create(
    const SecretServiceOptions& options) {
    return std::make_unique<secret_service::SecretServiceImpl>(options);
}

std::unique_ptr<SecretServiceProvider> SecretServiceProvider::create(
    std::unique_ptr<CredentialStore> store,
    const SecretServiceOptions& options) {
    return std::make_unique<secret_service::SecretServiceImpl>(options, std::move(store));
}

}  // namespace brocred
