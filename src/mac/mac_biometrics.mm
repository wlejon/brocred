#import "brocred/biometrics.h"

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

namespace brocred {

BiometricCapabilities get_biometric_capabilities() {
    BiometricCapabilities caps;
    caps.supported = false;
    caps.availability = BiometricAvailability::NotAvailable;
    caps.primary_type = BiometricType::None;

    @autoreleasepool {
        LAContext* ctx = [[LAContext alloc] init];
        NSError* error = nil;
        BOOL can = [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];

        if (ctx.biometryType == LABiometryTypeTouchID) {
            caps.has_fingerprint = true;
            caps.primary_type = BiometricType::Fingerprint;
            caps.sensor_name = "Apple Touch ID";
        } else if (ctx.biometryType == LABiometryTypeFaceID) {
            caps.has_face = true;
            caps.primary_type = BiometricType::Face;
            caps.sensor_name = "Apple Face ID";
        }

        if (can) {
            caps.supported = true;
            caps.availability = BiometricAvailability::Available;
            caps.details = "Biometric authentication is ready";
        } else if (error) {
            if (error.code == LAErrorBiometryNotEnrolled) {
                caps.supported = true;
                caps.availability = BiometricAvailability::NotConfigured;
                caps.details = "Biometric hardware present but no biometric identities are enrolled";
            } else if (error.code == LAErrorBiometryNotAvailable) {
                caps.supported = false;
                caps.availability = BiometricAvailability::NotAvailable;
                caps.details = "Biometric hardware not available on this device";
            } else if (error.code == LAErrorPasscodeNotSet) {
                caps.supported = true;
                caps.availability = BiometricAvailability::NotConfigured;
                caps.details = "Device passcode is not set";
            } else {
                caps.supported = (ctx.biometryType != LABiometryTypeNone);
                caps.availability = caps.supported ? BiometricAvailability::NotConfigured : BiometricAvailability::NotAvailable;
                caps.details = error.localizedDescription ? [error.localizedDescription UTF8String] : "Biometrics check failed";
            }
        }
    }

    return caps;
}

}  // namespace brocred
