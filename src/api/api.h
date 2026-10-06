#pragma once

#include "brocred/brocred.h"

#include <functional>
#include <memory>
#include <string>

namespace brocred::api {

/// Mounts `bro.cred` onto `bro` in the current Bronze realm.
void installCred();

/// Pumps async PAM auth results, biometrics events, and polkit requests on the JS thread.
void tickCredAsync();

/// Unregisters polkit agent and joins active auth threads.
void shutdownCredAsync();

/// Sets custom credential store backend (defaults to CredentialStore::create()).
void setStore(std::shared_ptr<brocred::CredentialStore> store);

/// Gets active credential store backend.
std::shared_ptr<brocred::CredentialStore> getStore();

} // namespace brocred::api

using brocred::api::installCred;
using brocred::api::tickCredAsync;
using brocred::api::shutdownCredAsync;
using brocred::api::setStore;
using brocred::api::getStore;
