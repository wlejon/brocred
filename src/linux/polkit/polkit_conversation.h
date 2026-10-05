// Conversation and PAM authentication handler for PolicyKit Agent.
#pragma once

#include "brocred/polkit_agent.h"
#include "brocred/verifier.h"

namespace brocred::polkit {

// Default conversation handler executing credential lookup / PAM verification
PolkitAuthResponse default_conversation_handler(const PolkitAuthRequest& request,
                                               const std::string& fallback_password);

}  // namespace brocred::polkit
