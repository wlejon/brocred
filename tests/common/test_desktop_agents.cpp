// PolkitAgent and SecretServiceProvider exist in every build. Where they can
// run (Linux with sd-bus) the Linux tests drive them over private buses; here
// the other configurations are held to what features.h promises: the factory
// returns an object, start() fails with a reason, nothing claims to be running,
// and the subject/identity helpers still build plain data.
#include "check.h"
#include "brocred/features.h"
#include "brocred/polkit_agent.h"
#include "brocred/secret_service.h"
#include "brocred/storage.h"

using namespace brocred;

static void test_report_matches_platform() {
    Features f = compiled_features();
    CHECK_EQ(f.polkit_agent, f.secret_service_provider);
#if defined(_WIN32) || defined(__APPLE__)
    CHECK(!f.polkit_agent);
#endif
}

static void test_polkit_unavailable() {
    auto agent = PolkitAgent::create();
    CHECK(agent != nullptr);
    if (!agent) return;
    Result r = agent->start();
    CHECK(!r.ok);
    CHECK(!r.error.empty());
    std::printf("PolkitAgent::start: %s\n", r.error.c_str());
    CHECK(!agent->is_running());
    CHECK(!agent->register_with_authority().ok);
    CHECK(!agent->is_registered());
    CHECK(!agent->process_one(0));

    PolkitAuthRequest req;
    req.cookie = "c1";
    PolkitAuthResponse resp = agent->handle_begin_authentication(req);
    CHECK(!resp.success);
    CHECK(!resp.error_message.empty());
    CHECK(!agent->has_active_session("c1"));
}

static void test_secret_service_unavailable() {
    auto provider = SecretServiceProvider::create();
    CHECK(provider != nullptr);
    if (!provider) return;
    Result r = provider->start();
    CHECK(!r.ok);
    CHECK(!r.error.empty());
    CHECK(!provider->is_running());
    CHECK(provider->list_collection_paths().empty());

    // A store handed in is handed back, untouched.
    StorageOptions mem;
    mem.backend = BackendType::Memory;
    auto store = CredentialStore::create(mem);
    CHECK(store != nullptr);
    CredentialStore* raw = store.get();
    auto with_store = SecretServiceProvider::create(std::move(store));
    CHECK(with_store != nullptr);
    if (with_store) CHECK(with_store->store() == raw);
}

static void test_plain_data() {
    PolkitSubject p = PolkitSubject::process(42, 7);
    CHECK(p.kind == PolkitSubject::Kind::UnixProcess);
    CHECK_EQ(p.pid, 42u);
    CHECK_EQ(p.start_time, 7u);
    PolkitSubject s = PolkitSubject::session("c2");
    CHECK(s.kind == PolkitSubject::Kind::UnixSession);
    CHECK_EQ(s.session_id, std::string("c2"));
    CHECK(PolkitSubject::current_process().pid != 0u);
    PolkitIdentity g = PolkitIdentity::group(5, "tty");
    CHECK(g.kind == PolkitIdentity::Kind::UnixGroup);
    CHECK_EQ(g.name, std::string("tty"));
}

int main() {
    test_report_matches_platform();
    test_plain_data();
    if (!compiled_features().polkit_agent) {
        test_polkit_unavailable();
        test_secret_service_unavailable();
    } else {
        // The real agents are driven over private buses by test_polkit_agent
        // and test_secret_service.
        std::printf("built with sd-bus: the unavailable paths are not compiled\n");
    }
    return bstest::finish("test_desktop_agents");
}
