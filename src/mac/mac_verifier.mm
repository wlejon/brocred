#import "brocred/verifier.h"

#import <Foundation/Foundation.h>
#import <OpenDirectory/OpenDirectory.h>

namespace brocred {

namespace {

NSString* get_current_mac_user() {
    return NSUserName();
}

}  // namespace

VerifyResult verify_password(const std::string& password) {
    return verify_password("", "", password);
}

VerifyResult verify_password(const std::string& username, const std::string& password) {
    return verify_password(username, "", password);
}

VerifyResult verify_password(const std::string& username, const std::string& domain_or_service,
                             const std::string& password) {
    @autoreleasepool {
        NSString* user = username.empty() ? get_current_mac_user()
                                          : [NSString stringWithUTF8String:username.c_str()];
        NSString* pass = [NSString stringWithUTF8String:password.c_str()];

        NSError* error = nil;
        ODSession* session = [ODSession defaultSession];
        ODNode* node = nil;

        if (!domain_or_service.empty()) {
            NSString* nodeName = [NSString stringWithUTF8String:domain_or_service.c_str()];
            node = [ODNode nodeWithSession:session name:nodeName error:&error];
        } else {
            node = [ODNode nodeWithSession:session type:kODNodeTypeLocalNodes error:&error];
        }

        if (!node) {
            std::string errStr = error ? [[error localizedDescription] UTF8String] : "Failed to open ODNode";
            return VerifyResult{false, "OpenDirectory node error: " + errStr};
        }

        ODRecord* record = [node recordWithRecordType:kODRecordTypeUsers
                                                 name:user
                                           attributes:nil
                                                error:&error];
        if (!record) {
            std::string errStr = error ? [[error localizedDescription] UTF8String] : "User record not found";
            return VerifyResult{false, "OpenDirectory user record error: " + errStr};
        }

        BOOL ok = [record verifyPassword:pass error:&error];
        if (ok) {
            return VerifyResult{true, ""};
        }

        std::string errStr = error ? [[error localizedDescription] UTF8String] : "Password verification failed";
        return VerifyResult{false, errStr};
    }
}

}  // namespace brocred
