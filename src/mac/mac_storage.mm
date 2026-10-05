#import "mac/mac_storage.h"
#import "common/file_keystore.h"
#import "common/memory_keystore.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>

namespace brocred {

namespace {

void apply_keychain_context(NSMutableDictionary* query, bool for_write) {
    if (for_write) {
        SecKeychainRef defKc = nullptr;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        if (SecKeychainCopyDefault(&defKc) == errSecSuccess && defKc) {
            query[(__bridge id)kSecUseKeychain] = (__bridge_transfer id)defKc;
        }
#pragma clang diagnostic pop
    } else {
        CFArrayRef searchList = nullptr;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        if (SecKeychainCopySearchList(&searchList) == errSecSuccess && searchList) {
            query[(__bridge id)kSecMatchSearchList] = (__bridge_transfer id)searchList;
        }
#pragma clang diagnostic pop
    }
}

NSData* encode_attributes(const std::map<std::string, std::string>& attrs) {
    if (attrs.empty()) return nil;
    NSMutableDictionary* dict = [NSMutableDictionary dictionaryWithCapacity:attrs.size()];
    for (const auto& [k, v] : attrs) {
        dict[[NSString stringWithUTF8String:k.c_str()]] = [NSString stringWithUTF8String:v.c_str()];
    }
    NSError* error = nil;
    return [NSJSONSerialization dataWithJSONObject:dict options:0 error:&error];
}

std::map<std::string, std::string> decode_attributes(NSData* data) {
    std::map<std::string, std::string> out;
    if (!data || data.length == 0) return out;
    NSError* error = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary* dict = (NSDictionary*)obj;
        for (NSString* k in dict) {
            id v = dict[k];
            if ([v isKindOfClass:[NSString class]]) {
                out[[k UTF8String]] = [(NSString*)v UTF8String];
            }
        }
    }
    return out;
}

std::string sec_error_message(OSStatus status) {
    CFStringRef errStr = SecCopyErrorMessageString(status, nullptr);
    if (errStr) {
        NSString* ns = (__bridge_transfer NSString*)errStr;
        return std::string([ns UTF8String]) + " (OSStatus " + std::to_string(status) + ")";
    }
    return "Keychain error code " + std::to_string(status);
}

std::chrono::system_clock::time_point nsdate_to_timepoint(NSDate* date) {
    if (!date) return std::chrono::system_clock::now();
    NSTimeInterval sec = [date timeIntervalSince1970];
    return std::chrono::system_clock::time_point(
        std::chrono::milliseconds(static_cast<int64_t>(sec * 1000.0)));
}

}  // namespace

std::unique_ptr<CredentialStore> CredentialStore::create() {
    return create(StorageOptions());
}

std::unique_ptr<CredentialStore> CredentialStore::create(const StorageOptions& options) {
    switch (options.backend) {
        case BackendType::Memory:
            return std::make_unique<MemoryKeystore>();
        case BackendType::FileKeystore:
            return std::make_unique<FileKeystore>(options.custom_file_path);
        case BackendType::System:
        case BackendType::Auto:
        default:
            return std::make_unique<MacKeychainStore>();
    }
}

Result MacKeychainStore::store_secret(const std::string& service, const std::string& account,
                                     const std::string& secret) {
    return store_secret(service, account, secret, {});
}

Result MacKeychainStore::store_secret(const std::string& service, const std::string& account,
                                     const std::string& secret,
                                     const std::map<std::string, std::string>& attributes) {
    if (service.empty()) {
        return Result::failure("Service name cannot be empty");
    }

    @autoreleasepool {
        NSString* nsService = [NSString stringWithUTF8String:service.c_str()];
        NSString* nsAccount = [NSString stringWithUTF8String:account.c_str()];
        NSData* nsSecret = [NSData dataWithBytes:secret.data() length:secret.size()];
        NSData* nsAttrs = encode_attributes(attributes);

        NSMutableDictionary* query = [NSMutableDictionary dictionary];
        query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
        query[(__bridge id)kSecAttrService] = nsService;
        query[(__bridge id)kSecAttrAccount] = nsAccount;
        query[(__bridge id)kSecValueData] = nsSecret;
        if (nsAttrs) {
            query[(__bridge id)kSecAttrGeneric] = nsAttrs;
        }
        apply_keychain_context(query, true);

        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, nullptr);
        if (status == errSecDuplicateItem) {
            NSMutableDictionary* match = [NSMutableDictionary dictionary];
            match[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
            match[(__bridge id)kSecAttrService] = nsService;
            match[(__bridge id)kSecAttrAccount] = nsAccount;
            apply_keychain_context(match, false);

            NSMutableDictionary* update = [NSMutableDictionary dictionary];
            update[(__bridge id)kSecValueData] = nsSecret;
            if (nsAttrs) {
                update[(__bridge id)kSecAttrGeneric] = nsAttrs;
            }

            status = SecItemUpdate((__bridge CFDictionaryRef)match,
                                   (__bridge CFDictionaryRef)update);
        }

        if (status != errSecSuccess) {
            return Result::failure("SecItemAdd/Update failed: " + sec_error_message(status));
        }

        CredentialChangedEvent ev;
        ev.change = CredentialChangedEvent::ChangeType::Stored;
        ev.service = service;
        ev.account = account;
        events_.push(std::move(ev));

        return Result::success();
    }
}

std::optional<std::string> MacKeychainStore::read_secret(const std::string& service,
                                                        const std::string& account) {
    auto cred = read_credential(service, account);
    if (!cred) return std::nullopt;
    return cred->secret;
}

std::optional<Credential> MacKeychainStore::read_credential(const std::string& service,
                                                           const std::string& account) {
    if (service.empty()) return std::nullopt;

    @autoreleasepool {
        NSMutableDictionary* query = [NSMutableDictionary dictionary];
        query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
        query[(__bridge id)kSecAttrService] = [NSString stringWithUTF8String:service.c_str()];
        if (!account.empty()) {
            query[(__bridge id)kSecAttrAccount] = [NSString stringWithUTF8String:account.c_str()];
        }
        query[(__bridge id)kSecReturnData] = @YES;
        query[(__bridge id)kSecReturnAttributes] = @YES;
        query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
        apply_keychain_context(query, false);

        CFTypeRef result = nullptr;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (status != errSecSuccess || !result) {
            return std::nullopt;
        }

        NSDictionary* dict = (__bridge_transfer NSDictionary*)result;
        NSData* secData = dict[(__bridge id)kSecValueData];
        NSString* foundAccount = dict[(__bridge id)kSecAttrAccount];
        NSData* attrData = dict[(__bridge id)kSecAttrGeneric];

        Credential cred;
        cred.service = service;
        cred.account = foundAccount ? [foundAccount UTF8String] : account;
        if (secData) {
            cred.secret.assign(static_cast<const char*>(secData.bytes), secData.length);
        }
        if (attrData) {
            cred.attributes = decode_attributes(attrData);
        }

        return cred;
    }
}

Result MacKeychainStore::delete_secret(const std::string& service, const std::string& account) {
    if (service.empty()) {
        return Result::failure("Service name cannot be empty");
    }

    @autoreleasepool {
        NSMutableDictionary* query = [NSMutableDictionary dictionary];
        query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
        query[(__bridge id)kSecAttrService] = [NSString stringWithUTF8String:service.c_str()];
        if (!account.empty()) {
            query[(__bridge id)kSecAttrAccount] = [NSString stringWithUTF8String:account.c_str()];
        }
        apply_keychain_context(query, false);

        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
        if (status != errSecSuccess) {
            return Result::failure("SecItemDelete failed: " + sec_error_message(status));
        }

        CredentialChangedEvent ev;
        ev.change = CredentialChangedEvent::ChangeType::Deleted;
        ev.service = service;
        ev.account = account;
        events_.push(std::move(ev));

        return Result::success();
    }
}

std::vector<CredentialMetadata> MacKeychainStore::list_credentials() {
    return list_credentials("");
}

std::vector<CredentialMetadata> MacKeychainStore::list_credentials(const std::string& service) {
    std::vector<CredentialMetadata> out;

    @autoreleasepool {
        NSMutableDictionary* query = [NSMutableDictionary dictionary];
        query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
        if (!service.empty()) {
            query[(__bridge id)kSecAttrService] = [NSString stringWithUTF8String:service.c_str()];
        }
        query[(__bridge id)kSecReturnAttributes] = @YES;
        query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
        apply_keychain_context(query, false);

        CFTypeRef result = nullptr;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (status != errSecSuccess || !result) {
            return out;
        }

        NSArray* items = (__bridge_transfer NSArray*)result;
        for (NSDictionary* item in items) {
            NSString* svc = item[(__bridge id)kSecAttrService];
            NSString* acc = item[(__bridge id)kSecAttrAccount];
            NSDate* modDate = item[(__bridge id)kSecAttrModificationDate];
            NSData* attrData = item[(__bridge id)kSecAttrGeneric];

            CredentialMetadata meta;
            meta.service = svc ? [svc UTF8String] : "";
            meta.account = acc ? [acc UTF8String] : "";
            meta.last_modified = nsdate_to_timepoint(modDate);
            if (attrData) {
                meta.attributes = decode_attributes(attrData);
            }
            out.push_back(std::move(meta));
        }
    }

    return out;
}

}  // namespace brocred
