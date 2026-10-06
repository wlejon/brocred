#include "../src/api/api.h"
#include "embed/embed.h"
#include "eval/eval.h"
#include "brocred/brocred.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "CHECK failed: " #cond " (" << __FILE__ << ":"        \
                      << __LINE__ << ")" << std::endl;                         \
            std::exit(1);                                                      \
        }                                                                      \
    } while (0)

#define CHECK_MSG(cond, msg)                                                   \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "CHECK failed: " #cond " (" << __FILE__ << ":"        \
                      << __LINE__ << "): " << (msg) << std::endl;              \
            std::exit(1);                                                      \
        }                                                                      \
    } while (0)

namespace {

bool pumpUntil(const std::function<bool()>& condition, int timeoutMs = 6000) {
    namespace ev = bronze::embed;
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start)
               .count() < timeoutMs) {
        brocred::api::tickCredAsync();
        ev::drainMicrotasks();
        if (condition()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    brocred::api::tickCredAsync();
    ev::drainMicrotasks();
    return condition();
}

} // namespace

int main() {
    namespace ev = bronze::embed;
    using namespace bronze::eval;

    std::cout << "Starting brocred JavaScript API test..." << std::endl;

    // 1. Isolate storage backend using an in-memory keystore for tests
    brocred::StorageOptions memOpts;
    memOpts.backend = brocred::BackendType::Memory;
    auto testStore = brocred::CredentialStore::create(memOpts);
    CHECK(testStore != nullptr);
    brocred::api::setStore(std::move(testStore));

    // 2. Install bro.cred into Bronze realm
    brocred::api::installCred();

    auto g = ev::globalValue("bro");
    CHECK(g.found);
    CHECK(ev::isObject(g.value));

    ev::Persistent cred(ev::getProperty(g.value, "cred"));
    CHECK(ev::isObject(cred.get()));
    std::cout << "  Mounted bro.cred successfully." << std::endl;

    // 3. Verify expected methods exist
    const char* methods[] = {
        "authenticate", "getBiometrics", "startBiometricAuth", "cancelBiometricAuth",
        "getSecret", "setSecret", "deleteSecret", "listSecrets",
        "registerPolkitAgent", "unregisterPolkitAgent", "onPolkitRequest"
    };
    for (const char* m : methods) {
        ev::Persistent fn(ev::getProperty(cred.get(), m));
        CHECK_MSG(ev::isFunction(fn.get()), std::string("Expected bro.cred.") + m + " to be a function");
        std::cout << "  Found bro.cred." << m << std::endl;
    }

    // 4. Test Secrets CRUD (Promise and Sync)
    std::cout << "Testing bro.cred secrets..." << std::endl;
    {
        // Test setSecret (Promise)
        std::string setScript =
            "(function() {\n"
            "  globalThis._setDone = false;\n"
            "  globalThis._setSuccess = false;\n"
            "  bro.cred.setSecret('test_svc', 'alice', 's3cr3t_123', { env: 'staging', team: 'sec' })\n"
            "    .then(res => {\n"
            "      globalThis._setSuccess = (res === true);\n"
            "      globalThis._setDone = true;\n"
            "    }).catch(err => {\n"
            "      globalThis._setDone = true;\n"
            "    });\n"
            "  return true;\n"
            "})()\n";
        auto r = evalScript(setScript);
        CHECK(!r.thrown);

        bool finished = pumpUntil([]() {
            auto v = evalScript("globalThis._setDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK_MSG(finished, "setSecret promise timed out");

        auto checkSet = evalScript("globalThis._setSuccess;");
        CHECK(ev::isBool(checkSet.value) && ev::toBool(checkSet.value));

        // Test getSecret (Promise)
        std::string getScript =
            "(function() {\n"
            "  globalThis._getDone = false;\n"
            "  globalThis._secretVal = null;\n"
            "  bro.cred.getSecret('test_svc', 'alice')\n"
            "    .then(val => {\n"
            "      globalThis._secretVal = val;\n"
            "      globalThis._getDone = true;\n"
            "    }).catch(err => {\n"
            "      globalThis._getDone = true;\n"
            "    });\n"
            "  return true;\n"
            "})()\n";
        r = evalScript(getScript);
        CHECK(!r.thrown);

        finished = pumpUntil([]() {
            auto v = evalScript("globalThis._getDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK_MSG(finished, "getSecret promise timed out");

        auto checkGet = evalScript("globalThis._secretVal;");
        CHECK(ev::isString(checkGet.value));
        CHECK(ev::toUtf8(checkGet.value) == "s3cr3t_123");

        // Test listSecrets (Promise)
        std::string listScript =
            "(function() {\n"
            "  globalThis._listDone = false;\n"
            "  globalThis._listItems = null;\n"
            "  bro.cred.listSecrets('test_svc')\n"
            "    .then(items => {\n"
            "      globalThis._listItems = items;\n"
            "      globalThis._listDone = true;\n"
            "    }).catch(err => {\n"
            "      globalThis._listDone = true;\n"
            "    });\n"
            "  return true;\n"
            "})()\n";
        r = evalScript(listScript);
        CHECK(!r.thrown);

        finished = pumpUntil([]() {
            auto v = evalScript("globalThis._listDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK_MSG(finished, "listSecrets promise timed out");

        auto checkList = evalScript(
            "(function() {\n"
            "  const items = globalThis._listItems;\n"
            "  if (!Array.isArray(items) || items.length !== 1) return false;\n"
            "  if (items[0].service !== 'test_svc' || items[0].account !== 'alice') return false;\n"
            "  if (!items[0].meta || items[0].meta.env !== 'staging') return false;\n"
            "  return true;\n"
            "})()\n"
        );
        CHECK(!checkList.thrown && ev::isBool(checkList.value) && ev::toBool(checkList.value));

        // Test synchronous secret APIs
        auto syncSet = evalScript("bro.cred.setSecretSync('test_svc', 'bob', 'bob_pass', { role: 'tester' });");
        CHECK(!syncSet.thrown && ev::isBool(syncSet.value) && ev::toBool(syncSet.value));

        auto syncGet = evalScript("bro.cred.getSecretSync('test_svc', 'bob');");
        CHECK(!syncGet.thrown && ev::isString(syncGet.value) && ev::toUtf8(syncGet.value) == "bob_pass");

        auto syncList = evalScript("bro.cred.listSecretsSync('test_svc');");
        CHECK(!syncList.thrown && ev::isObject(syncList.value));
        auto syncLen = evalScript("bro.cred.listSecretsSync('test_svc').length;");
        CHECK(!syncLen.thrown && ev::isNumber(syncLen.value) && ev::toDouble(syncLen.value) == 2.0);

        // Test deleteSecret (Promise)
        std::string delScript =
            "(function() {\n"
            "  globalThis._delDone = false;\n"
            "  globalThis._delSuccess = false;\n"
            "  bro.cred.deleteSecret('test_svc', 'alice')\n"
            "    .then(res => {\n"
            "      globalThis._delSuccess = (res === true);\n"
            "      globalThis._delDone = true;\n"
            "    }).catch(err => {\n"
            "      globalThis._delDone = true;\n"
            "    });\n"
            "  return true;\n"
            "})()\n";
        r = evalScript(delScript);
        CHECK(!r.thrown);

        finished = pumpUntil([]() {
            auto v = evalScript("globalThis._delDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK_MSG(finished, "deleteSecret promise timed out");

        auto checkDel = evalScript("globalThis._delSuccess;");
        CHECK(ev::isBool(checkDel.value) && ev::toBool(checkDel.value));

        // Alice is gone, Bob remains
        auto getAfterDel = evalScript("bro.cred.getSecretSync('test_svc', 'alice');");
        CHECK(!getAfterDel.thrown && ev::isNull(getAfterDel.value));

        auto delBobSync = evalScript("bro.cred.deleteSecretSync('test_svc', 'bob');");
        CHECK(!delBobSync.thrown && ev::isBool(delBobSync.value) && ev::toBool(delBobSync.value));

        std::cout << "  Secret CRUD operations [PASS]" << std::endl;
    }

    // 5. Test Biometrics
    std::cout << "Testing bro.cred biometrics..." << std::endl;
    {
        auto bioRes = evalScript(
            "(function() {\n"
            "  const bio = bro.cred.getBiometrics();\n"
            "  if (typeof bio !== 'object' || bio === null) return false;\n"
            "  if (typeof bio.supported !== 'boolean') return false;\n"
            "  if (typeof bio.hasFingerprint !== 'boolean') return false;\n"
            "  if (typeof bio.hasFace !== 'boolean') return false;\n"
            "  if (typeof bio.hasIris !== 'boolean') return false;\n"
            "  if (typeof bio.availability !== 'string') return false;\n"
            "  if (typeof bio.primaryType !== 'string') return false;\n"
            "  return true;\n"
            "})()\n"
        );
        CHECK(!bioRes.thrown && ev::isBool(bioRes.value) && ev::toBool(bioRes.value));

        // Test startBiometricAuth()
        std::string startBioScript =
            "(function() {\n"
            "  globalThis._bioDone = false;\n"
            "  globalThis._bioRes = null;\n"
            "  bro.cred.startBiometricAuth()\n"
            "    .then(res => {\n"
            "      globalThis._bioRes = res;\n"
            "      globalThis._bioDone = true;\n"
            "    }).catch(err => {\n"
            "      globalThis._bioDone = true;\n"
            "    });\n"
            "  return true;\n"
            "})()\n";
        auto r = evalScript(startBioScript);
        CHECK(!r.thrown);

        bool finished = pumpUntil([]() {
            auto v = evalScript("globalThis._bioDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK_MSG(finished, "startBiometricAuth promise timed out");

        auto checkBioAuth = evalScript(
            "(function() {\n"
            "  const r = globalThis._bioRes;\n"
            "  if (typeof r !== 'object' || r === null) return false;\n"
            "  if (typeof r.success !== 'boolean') return false;\n"
            "  if (typeof r.method !== 'string') return false;\n"
            "  return true;\n"
            "})()\n"
        );
        CHECK(!checkBioAuth.thrown && ev::isBool(checkBioAuth.value) && ev::toBool(checkBioAuth.value));

        // Test cancelBiometricAuth()
        std::string cancelBioScript =
            "(function() {\n"
            "  globalThis._bioCancelDone = false;\n"
            "  globalThis._bioCancelRes = null;\n"
            "  bro.cred.startBiometricAuth()\n"
            "    .then(res => {\n"
            "      globalThis._bioCancelRes = res;\n"
            "      globalThis._bioCancelDone = true;\n"
            "    });\n"
            "  bro.cred.cancelBiometricAuth();\n"
            "  return true;\n"
            "})()\n";
        r = evalScript(cancelBioScript);
        CHECK(!r.thrown);

        finished = pumpUntil([]() {
            auto v = evalScript("globalThis._bioCancelDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK_MSG(finished, "cancelBiometricAuth promise timed out");

        auto checkBioCancel = evalScript(
            "(function() {\n"
            "  const r = globalThis._bioCancelRes;\n"
            "  if (typeof r !== 'object' || r === null) return false;\n"
            "  if (r.success !== false) return false;\n"
            "  return true;\n"
            "})()\n"
        );
        CHECK(!checkBioCancel.thrown && ev::isBool(checkBioCancel.value) && ev::toBool(checkBioCancel.value));

        std::cout << "  Biometrics [PASS]" << std::endl;
    }

    // 6. Test Authentication (PAM / Verifier)
    std::cout << "Testing bro.cred.authenticate..." << std::endl;
    {
        std::string authScript =
            "(function() {\n"
            "  globalThis._authDone = false;\n"
            "  globalThis._authResult = null;\n"
            "  bro.cred.authenticate('nonexistent_user_test_xyz', 'incorrect_password_123')\n"
            "    .then(success => {\n"
            "      globalThis._authResult = success;\n"
            "      globalThis._authDone = true;\n"
            "    }).catch(err => {\n"
            "      globalThis._authDone = true;\n"
            "    });\n"
            "  return true;\n"
            "})()\n";
        auto r = evalScript(authScript);
        CHECK(!r.thrown);

        bool finished = pumpUntil([]() {
            auto v = evalScript("globalThis._authDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        }, 8000);
        CHECK_MSG(finished, "authenticate promise timed out");

        auto checkAuth = evalScript("globalThis._authResult;");
        CHECK(!checkAuth.thrown && ev::isBool(checkAuth.value));
        // Nonexistent user must fail verification
        CHECK(!ev::toBool(checkAuth.value));

        // Test sync authentication
        auto syncAuth = evalScript("bro.cred.authenticateSync('nonexistent_user_test_xyz', 'wrong');");
        CHECK(!syncAuth.thrown && ev::isBool(syncAuth.value));
        CHECK(!ev::toBool(syncAuth.value));

        std::cout << "  Authentication [PASS]" << std::endl;
    }

    // 7. Test PolicyKit Agent callbacks & request dispatch
    std::cout << "Testing bro.cred PolicyKit Agent..." << std::endl;
    {
        std::string polkitScript =
            "(function() {\n"
            "  globalThis._polkitReceived = null;\n"
            "  const subHandle = bro.cred.onPolkitRequest(req => {\n"
            "    globalThis._polkitReceived = {\n"
            "      actionId: req.actionId,\n"
            "      message: req.message,\n"
            "      cookie: req.cookie\n"
            "    };\n"
            "    req.submitResponse(true);\n"
            "  });\n"
            "  if (typeof subHandle !== 'object' || typeof subHandle.cancel !== 'function') return false;\n"
            "  return true;\n"
            "})()\n";
        auto r = evalScript(polkitScript);
        CHECK(!r.thrown && ev::isBool(r.value) && ev::toBool(r.value));

        // Dispatch a test polkit request directly
        auto dispatchRes = evalScript(
            "bro.cred.dispatchPolkitRequest({\n"
            "  actionId: 'org.freedesktop.policykit.exec',\n"
            "  message: 'Authenticate to run privileged command',\n"
            "  cookie: 'test-cookie-1234'\n"
            "});\n"
        );
        CHECK(!dispatchRes.thrown && ev::isObject(dispatchRes.value));

        bool finished = pumpUntil([]() {
            auto v = evalScript("globalThis._polkitReceived !== null;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK_MSG(finished, "onPolkitRequest callback not received");

        auto checkPolkit = evalScript(
            "(function() {\n"
            "  const r = globalThis._polkitReceived;\n"
            "  if (!r) return false;\n"
            "  if (r.actionId !== 'org.freedesktop.policykit.exec') return false;\n"
            "  if (r.cookie !== 'test-cookie-1234') return false;\n"
            "  return true;\n"
            "})()\n"
        );
        CHECK(!checkPolkit.thrown && ev::isBool(checkPolkit.value) && ev::toBool(checkPolkit.value));

        // Test register / unregister agent methods
        auto regRes = evalScript("bro.cred.registerPolkitAgent({ registerWithAuthority: false });");
        CHECK(!regRes.thrown && ev::isBool(regRes.value));

        auto unregRes = evalScript("bro.cred.unregisterPolkitAgent();");
        CHECK(!unregRes.thrown && ev::isBool(unregRes.value) && ev::toBool(unregRes.value));

        std::cout << "  PolicyKit Agent [PASS]" << std::endl;
    }

    // 8. Test Shutdown
    std::cout << "Testing bro.cred.shutdownCredAsync..." << std::endl;
    brocred::api::shutdownCredAsync();
    std::cout << "  shutdownCredAsync [PASS]" << std::endl;

    std::cout << "All brocred JavaScript API tests completed successfully!" << std::endl;
    return 0;
}
