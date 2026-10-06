#include "host_cred_internal.h"
#include "brocred/storage.h"

#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace brocred::api {

namespace {

std::map<std::string, std::string> parseMeta(Value metaVal) {
    std::map<std::string, std::string> map;
    if (!ev::isObject(metaVal)) return map;
    ev::Persistent meta(metaVal);

    auto gObject = ev::globalValue("Object");
    if (!gObject.found || !ev::isObject(gObject.value)) return map;
    ev::Persistent objCtor(gObject.value);
    ev::Persistent keysFn(ev::getProperty(objCtor.get(), "keys"));
    if (!ev::isFunction(keysFn.get())) return map;

    Value arg = meta.get();
    auto kres = ev::call(keysFn.get(), objCtor.get(), std::span<const Value>(&arg, 1));
    if (kres.thrown || !ev::isObject(kres.value)) return map;

    ev::Persistent keysArr(kres.value);
    ev::Persistent lenVal(ev::getProperty(keysArr.get(), "length"));
    uint32_t len = ev::isNumber(lenVal.get()) ? static_cast<uint32_t>(ev::toDouble(lenVal.get())) : 0;

    for (uint32_t i = 0; i < len; ++i) {
        ev::Persistent keyVal(ev::getElement(keysArr.get(), i));
        if (!ev::isString(keyVal.get())) continue;
        std::string k = ev::toUtf8(keyVal.get());
        ev::Persistent vVal(ev::getProperty(meta.get(), k));
        std::string v;
        if (ev::isString(vVal.get())) {
            v = ev::toUtf8(vVal.get());
        } else if (ev::isNumber(vVal.get())) {
            v = std::to_string(ev::toDouble(vVal.get()));
        } else if (ev::isBool(vVal.get())) {
            v = ev::toBool(vVal.get()) ? "true" : "false";
        }
        map[k] = v;
    }
    return map;
}

bool isSyncOption(Value optVal) {
    if (!ev::isObject(optVal)) return false;
    ev::Persistent opt(optVal);
    ev::Persistent syncVal(ev::getProperty(opt.get(), "sync"));
    return ev::isBool(syncVal.get()) && ev::toBool(syncVal.get());
}

Value credListToJs(const std::vector<brocred::CredentialMetadata>& creds) {
    ev::Persistent arr(ev::makeArray(static_cast<uint32_t>(creds.size())));
    for (size_t i = 0; i < creds.size(); ++i) {
        const auto& c = creds[i];
        ObjectBuilder item;
        item.set("service", c.service);
        item.set("account", c.account);

        ObjectBuilder meta;
        for (const auto& [k, v] : c.attributes) {
            meta.set(k, v);
        }
        item.set("meta", meta.get());
        item.set("attributes", meta.get());

        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            c.last_modified.time_since_epoch()).count();
        item.set("lastModified", static_cast<double>(ms));

        arr.set(ev::setElement(arr.get(), static_cast<uint32_t>(i), item.get()));
    }
    return arr.get();
}

} // namespace

void handleCredentialChangedEvent(const brocred::CredentialChangedEvent& /*evItem*/) {
    // Currently storage change events do not require special JS dispatch,
    // but hook is available for reactive store notifications.
}

void installSecretsOnto(Value credObj) {
    ObjectBuilder cred(credObj);

    // bro.cred.getSecret(service, account, options?) -> Promise<string | null> / string | null
    cred.def("getSecret", 2, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());
        ev::Persistent p1(args.size() > 1 ? args[1] : ev::undefined());
        ev::Persistent p2(args.size() > 2 ? args[2] : ev::undefined());

        std::string service = ev::isString(p0.get()) ? ev::toUtf8(p0.get()) : "";
        std::string account = ev::isString(p1.get()) ? ev::toUtf8(p1.get()) : "";

        if (isSyncOption(p2.get())) {
            auto sec = activeStore()->read_secret(service, account);
            return sec.has_value() ? ev::fromUtf8(*sec) : ev::null();
        }

        ev::Persistent promise(ev::createPromise());
        auto job = std::make_shared<CredAsyncJob>();
        job->promise.set(promise.get());

        auto outSec = std::make_shared<std::optional<std::string>>();
        job->run = [service, account, outSec]() {
            *outSec = activeStore()->read_secret(service, account);
        };
        job->settle = [outSec](Value pVal) {
            if (outSec->has_value()) {
                ev::Persistent val(ev::fromUtf8(**outSec));
                ev::resolvePromise(pVal, val.get());
            } else {
                ev::resolvePromise(pVal, ev::null());
            }
        };

        trackAsyncJob(job);
        return promise.get();
    });

    // bro.cred.getSecretSync(service, account) -> string | null
    cred.def("getSecretSync", 2, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());
        ev::Persistent p1(args.size() > 1 ? args[1] : ev::undefined());

        std::string service = ev::isString(p0.get()) ? ev::toUtf8(p0.get()) : "";
        std::string account = ev::isString(p1.get()) ? ev::toUtf8(p1.get()) : "";

        auto sec = activeStore()->read_secret(service, account);
        return sec.has_value() ? ev::fromUtf8(*sec) : ev::null();
    });

    // bro.cred.setSecret(service, account, secret, meta?, options?) -> Promise<boolean> / boolean
    cred.def("setSecret", 3, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());
        ev::Persistent p1(args.size() > 1 ? args[1] : ev::undefined());
        ev::Persistent p2(args.size() > 2 ? args[2] : ev::undefined());
        ev::Persistent p3(args.size() > 3 ? args[3] : ev::undefined());
        ev::Persistent p4(args.size() > 4 ? args[4] : ev::undefined());

        std::string service = ev::isString(p0.get()) ? ev::toUtf8(p0.get()) : "";
        std::string account = ev::isString(p1.get()) ? ev::toUtf8(p1.get()) : "";
        std::string secret = ev::isString(p2.get()) ? ev::toUtf8(p2.get()) : "";
        auto metaMap = parseMeta(p3.get());

        if (isSyncOption(p3.get()) || isSyncOption(p4.get())) {
            brocred::Result res = activeStore()->store_secret(service, account, secret, metaMap);
            return ev::fromBool(res.ok);
        }

        ev::Persistent promise(ev::createPromise());
        auto job = std::make_shared<CredAsyncJob>();
        job->promise.set(promise.get());

        auto outRes = std::make_shared<brocred::Result>();
        job->run = [service, account, secret, metaMap, outRes]() {
            *outRes = activeStore()->store_secret(service, account, secret, metaMap);
        };
        job->settle = [outRes](Value pVal) {
            ev::resolvePromise(pVal, ev::fromBool(outRes->ok));
        };

        trackAsyncJob(job);
        return promise.get();
    });

    // bro.cred.setSecretSync(service, account, secret, meta?) -> boolean
    cred.def("setSecretSync", 3, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());
        ev::Persistent p1(args.size() > 1 ? args[1] : ev::undefined());
        ev::Persistent p2(args.size() > 2 ? args[2] : ev::undefined());
        ev::Persistent p3(args.size() > 3 ? args[3] : ev::undefined());

        std::string service = ev::isString(p0.get()) ? ev::toUtf8(p0.get()) : "";
        std::string account = ev::isString(p1.get()) ? ev::toUtf8(p1.get()) : "";
        std::string secret = ev::isString(p2.get()) ? ev::toUtf8(p2.get()) : "";
        auto metaMap = parseMeta(p3.get());

        brocred::Result res = activeStore()->store_secret(service, account, secret, metaMap);
        return ev::fromBool(res.ok);
    });

    // bro.cred.deleteSecret(service, account, options?) -> Promise<boolean> / boolean
    cred.def("deleteSecret", 2, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());
        ev::Persistent p1(args.size() > 1 ? args[1] : ev::undefined());
        ev::Persistent p2(args.size() > 2 ? args[2] : ev::undefined());

        std::string service = ev::isString(p0.get()) ? ev::toUtf8(p0.get()) : "";
        std::string account = ev::isString(p1.get()) ? ev::toUtf8(p1.get()) : "";

        if (isSyncOption(p2.get())) {
            brocred::Result res = activeStore()->delete_secret(service, account);
            return ev::fromBool(res.ok);
        }

        ev::Persistent promise(ev::createPromise());
        auto job = std::make_shared<CredAsyncJob>();
        job->promise.set(promise.get());

        auto outRes = std::make_shared<brocred::Result>();
        job->run = [service, account, outRes]() {
            *outRes = activeStore()->delete_secret(service, account);
        };
        job->settle = [outRes](Value pVal) {
            ev::resolvePromise(pVal, ev::fromBool(outRes->ok));
        };

        trackAsyncJob(job);
        return promise.get();
    });

    // bro.cred.deleteSecretSync(service, account) -> boolean
    cred.def("deleteSecretSync", 2, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());
        ev::Persistent p1(args.size() > 1 ? args[1] : ev::undefined());

        std::string service = ev::isString(p0.get()) ? ev::toUtf8(p0.get()) : "";
        std::string account = ev::isString(p1.get()) ? ev::toUtf8(p1.get()) : "";

        brocred::Result res = activeStore()->delete_secret(service, account);
        return ev::fromBool(res.ok);
    });

    // bro.cred.listSecrets(service?, options?) -> Promise<Array<{ service, account, meta }>>
    cred.def("listSecrets", 0, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());
        ev::Persistent p1(args.size() > 1 ? args[1] : ev::undefined());

        std::string service;
        bool hasService = false;
        if (ev::isString(p0.get())) {
            service = ev::toUtf8(p0.get());
            hasService = true;
        }

        if (isSyncOption(p0.get()) || isSyncOption(p1.get())) {
            auto list = hasService ? activeStore()->list_credentials(service)
                                   : activeStore()->list_credentials();
            return credListToJs(list);
        }

        ev::Persistent promise(ev::createPromise());
        auto job = std::make_shared<CredAsyncJob>();
        job->promise.set(promise.get());

        auto outList = std::make_shared<std::vector<brocred::CredentialMetadata>>();
        job->run = [service, hasService, outList]() {
            *outList = hasService ? activeStore()->list_credentials(service)
                                  : activeStore()->list_credentials();
        };
        job->settle = [outList](Value pVal) {
            ev::Persistent res(credListToJs(*outList));
            ev::resolvePromise(pVal, res.get());
        };

        trackAsyncJob(job);
        return promise.get();
    });

    // bro.cred.listSecretsSync(service?) -> Array<{ service, account, meta }>
    cred.def("listSecretsSync", 0, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());
        std::string service;
        bool hasService = false;
        if (ev::isString(p0.get())) {
            service = ev::toUtf8(p0.get());
            hasService = true;
        }
        auto list = hasService ? activeStore()->list_credentials(service)
                               : activeStore()->list_credentials();
        return credListToJs(list);
    });
}

} // namespace brocred::api
