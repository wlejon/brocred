// Factory method for PolkitAgent.
#include "brocred/polkit_agent.h"
#include "linux/polkit/polkit_agent_impl.h"

namespace brocred {

std::unique_ptr<PolkitAgent> PolkitAgent::create(
    const PolkitAgentOptions& options,
    PolkitAuthHandler handler) {
    return std::make_unique<polkit::PolkitAgentImpl>(options, std::move(handler));
}

}  // namespace brocred
