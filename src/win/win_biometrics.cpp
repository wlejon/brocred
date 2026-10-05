#include "brocred/biometrics.h"

#include <windows.h>
#include <winbio.h>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.UI.h>

#include <string>

namespace brocred {

namespace {

std::string wide_to_utf8(const wchar_t* wstr) {
    if (!wstr || !*wstr) return "";
    int count = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (count <= 1) return "";
    std::string out(count - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, out.data(), count, nullptr, nullptr);
    return out;
}

}  // namespace

BiometricCapabilities get_biometric_capabilities() {
    BiometricCapabilities caps;
    caps.supported = false;
    caps.availability = BiometricAvailability::NotAvailable;

    // 1. Inspect hardware biometric units via WinBio
    WINBIO_UNIT_SCHEMA* unit_schema = nullptr;
    SIZE_T unit_count = 0;
    HRESULT hr = WinBioEnumBiometricUnits(
        WINBIO_TYPE_FINGERPRINT | WINBIO_TYPE_FACIAL_FEATURES,
        &unit_schema, &unit_count);

    if (SUCCEEDED(hr) && unit_schema && unit_count > 0) {
        caps.supported = true;
        for (SIZE_T i = 0; i < unit_count; ++i) {
            if (unit_schema[i].BiometricFactor & WINBIO_TYPE_FINGERPRINT) {
                caps.has_fingerprint = true;
            }
            if (unit_schema[i].BiometricFactor & WINBIO_TYPE_FACIAL_FEATURES) {
                caps.has_face = true;
            }
            if (caps.sensor_name.empty() && unit_schema[i].Description) {
                caps.sensor_name = wide_to_utf8(unit_schema[i].Description);
            }
        }
        WinBioFree(unit_schema);
    }

    // 2. Query Windows Hello / UserConsentVerifier
    try {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
        using namespace winrt::Windows::Security::Credentials::UI;
        UserConsentVerifierAvailability ucv = UserConsentVerifier::CheckAvailabilityAsync().get();
        switch (ucv) {
            case UserConsentVerifierAvailability::Available:
                caps.supported = true;
                caps.availability = BiometricAvailability::Available;
                caps.details = "Windows Hello is available and configured";
                break;
            case UserConsentVerifierAvailability::DeviceNotPresent:
                if (!caps.supported) {
                    caps.availability = BiometricAvailability::NotAvailable;
                    caps.details = "No biometric hardware or Windows Hello device present";
                }
                break;
            case UserConsentVerifierAvailability::NotConfiguredForUser:
                caps.supported = true;
                caps.availability = BiometricAvailability::NotConfigured;
                caps.details = "Biometric device present but not configured for current user";
                break;
            case UserConsentVerifierAvailability::DisabledByPolicy:
                caps.supported = true;
                caps.availability = BiometricAvailability::DisabledByPolicy;
                caps.details = "Windows Hello is disabled by administrative policy";
                break;
            case UserConsentVerifierAvailability::DeviceBusy:
                caps.supported = true;
                caps.availability = BiometricAvailability::Available;
                caps.details = "Biometric device is currently busy";
                break;
        }
    } catch (...) {
        // Fallback: if WinRT is unavailable, rely on WinBio hardware report
        if (caps.supported) {
            caps.availability = BiometricAvailability::NotConfigured;
            caps.details = "Biometric hardware present via WinBio";
        } else {
            caps.availability = BiometricAvailability::NotAvailable;
            caps.details = "Windows Hello / WinRT check unavailable";
        }
    }

    if (caps.has_fingerprint && caps.has_face) {
        caps.primary_type = BiometricType::Multiple;
    } else if (caps.has_fingerprint) {
        caps.primary_type = BiometricType::Fingerprint;
    } else if (caps.has_face) {
        caps.primary_type = BiometricType::Face;
    } else if (caps.availability == BiometricAvailability::Available) {
        caps.primary_type = BiometricType::Multiple;
    } else {
        caps.primary_type = BiometricType::None;
    }

    return caps;
}

}  // namespace brocred
