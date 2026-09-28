//go:build darwin
// +build darwin

package unlock

/*
#cgo CFLAGS: -fblocks
#cgo LDFLAGS: -framework CoreFoundation -framework Security -framework Foundation -framework LocalAuthentication

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

int enpasscli_authenticate_biometric(const char *reasonChars, char **errorOut);

static CFStringRef enpasscli_cf_string(const char *value) {
	if (value == NULL) {
		return NULL;
	}
	return CFStringCreateWithCString(NULL, value, kCFStringEncodingUTF8);
}

static CFMutableDictionaryRef enpasscli_keychain_query(CFStringRef service, CFStringRef account) {
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (query == NULL) {
		return NULL;
	}

	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, service);
	CFDictionarySetValue(query, kSecAttrAccount, account);
	return query;
}

static OSStatus enpasscli_keychain_delete_refs(CFStringRef service, CFStringRef account) {
	CFMutableDictionaryRef query = enpasscli_keychain_query(service, account);
	if (query == NULL) {
		return errSecAllocate;
	}

	OSStatus status = SecItemDelete((CFDictionaryRef)query);
	CFRelease(query);
	return status;
}

static OSStatus enpasscli_keychain_get(const char *serviceChars, const char *accountChars, CFDataRef *result) {
	if (result == NULL) {
		return errSecParam;
	}
	*result = NULL;

	CFStringRef service = enpasscli_cf_string(serviceChars);
	CFStringRef account = enpasscli_cf_string(accountChars);
	if (service == NULL || account == NULL) {
		if (service != NULL) {
			CFRelease(service);
		}
		if (account != NULL) {
			CFRelease(account);
		}
		return errSecParam;
	}

	CFMutableDictionaryRef query = enpasscli_keychain_query(service, account);
	CFRelease(service);
	CFRelease(account);
	if (query == NULL) {
		return errSecAllocate;
	}

	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

	CFTypeRef found = NULL;
	OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, &found);
	CFRelease(query);
	if (status == errSecSuccess) {
		*result = (CFDataRef)found;
	} else if (found != NULL) {
		CFRelease(found);
	}

	return status;
}

static OSStatus enpasscli_keychain_set(const char *serviceChars, const char *accountChars, const void *secretBytes, CFIndex secretLen) {
	if (secretBytes == NULL || secretLen <= 0) {
		return errSecParam;
	}

	CFStringRef service = enpasscli_cf_string(serviceChars);
	CFStringRef account = enpasscli_cf_string(accountChars);
	if (service == NULL || account == NULL) {
		if (service != NULL) {
			CFRelease(service);
		}
		if (account != NULL) {
			CFRelease(account);
		}
		return errSecParam;
	}

	CFMutableDictionaryRef query = enpasscli_keychain_query(service, account);
	if (query == NULL) {
		CFRelease(service);
		CFRelease(account);
		return errSecAllocate;
	}

	CFDataRef secret = CFDataCreate(NULL, (const UInt8 *)secretBytes, secretLen);
	if (secret == NULL) {
		CFRelease(query);
		CFRelease(service);
		CFRelease(account);
		return errSecAllocate;
	}
	CFDictionarySetValue(query, kSecValueData, secret);
	CFRelease(secret);

	CFStringRef label = enpasscli_cf_string("enpass-cli biometric unlock key");
	if (label != NULL) {
		CFDictionarySetValue(query, kSecAttrLabel, label);
		CFRelease(label);
	}

	OSStatus status = SecItemAdd((CFDictionaryRef)query, NULL);
	if (status == errSecDuplicateItem) {
		OSStatus deleteStatus = enpasscli_keychain_delete_refs(service, account);
		if (deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound) {
			status = SecItemAdd((CFDictionaryRef)query, NULL);
		} else {
			status = deleteStatus;
		}
	}

	CFRelease(query);
	CFRelease(service);
	CFRelease(account);
	return status;
}

static OSStatus enpasscli_keychain_delete(const char *serviceChars, const char *accountChars) {
	CFStringRef service = enpasscli_cf_string(serviceChars);
	CFStringRef account = enpasscli_cf_string(accountChars);
	if (service == NULL || account == NULL) {
		if (service != NULL) {
			CFRelease(service);
		}
		if (account != NULL) {
			CFRelease(account);
		}
		return errSecParam;
	}

	OSStatus status = enpasscli_keychain_delete_refs(service, account);
	CFRelease(service);
	CFRelease(account);
	return status;
}

static CFIndex enpasscli_cf_data_length(CFDataRef data) {
	return CFDataGetLength(data);
}

static const UInt8 *enpasscli_cf_data_bytes(CFDataRef data) {
	return CFDataGetBytePtr(data);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/sirupsen/logrus"
)

const biometricService = "enpass-cli"

type BiometricStore struct {
	logger              logrus.Logger
	account             string
	wasReadSuccessfully bool
}

func NewBiometricStore(account string, logLevel logrus.Level) (*BiometricStore, error) {
	if account == "" {
		return nil, errors.New("empty biometric store account")
	}

	store := BiometricStore{
		logger:  *logrus.New(),
		account: account,
	}
	store.logger.SetLevel(logLevel)
	return &store, nil
}

func (store *BiometricStore) Read() ([]byte, error) {
	store.logger.Debug("reading credentials from macOS keychain")
	if err := authenticateBiometric("Unlock Enpass vault with Touch ID"); err != nil {
		return nil, err
	}

	service := C.CString(biometricService)
	defer C.free(unsafe.Pointer(service))
	account := C.CString(store.account)
	defer C.free(unsafe.Pointer(account))

	var data C.CFDataRef
	status := C.enpasscli_keychain_get(service, account, &data)
	if status == C.errSecItemNotFound {
		store.logger.Debug("biometric credentials not found")
		return nil, nil
	}
	if status != C.errSecSuccess {
		return nil, keychainError("read", status)
	}
	defer C.CFRelease(C.CFTypeRef(data))

	length := C.enpasscli_cf_data_length(data)
	if length <= 0 {
		return nil, errors.New("empty biometric credentials")
	}
	bytes := C.enpasscli_cf_data_bytes(data)
	if bytes == nil {
		return nil, errors.New("could not read biometric credentials")
	}

	store.wasReadSuccessfully = true
	return C.GoBytes(unsafe.Pointer(bytes), C.int(length)), nil
}

func (store *BiometricStore) Write(dbKey []byte) error {
	if store.wasReadSuccessfully {
		return nil
	}
	if len(dbKey) == 0 {
		return errors.New("empty database key")
	}

	store.logger.Debug("writing credentials to macOS keychain")

	service := C.CString(biometricService)
	defer C.free(unsafe.Pointer(service))
	account := C.CString(store.account)
	defer C.free(unsafe.Pointer(account))

	status := C.enpasscli_keychain_set(service, account, unsafe.Pointer(&dbKey[0]), C.CFIndex(len(dbKey)))
	if status != C.errSecSuccess {
		return keychainError("write", status)
	}

	return nil
}

func (store *BiometricStore) Clean() error {
	store.wasReadSuccessfully = false

	service := C.CString(biometricService)
	defer C.free(unsafe.Pointer(service))
	account := C.CString(store.account)
	defer C.free(unsafe.Pointer(account))

	status := C.enpasscli_keychain_delete(service, account)
	if status != C.errSecSuccess && status != C.errSecItemNotFound {
		return keychainError("delete", status)
	}

	return nil
}

func keychainError(operation string, status C.OSStatus) error {
	return fmt.Errorf("macOS keychain %s failed: OSStatus %d", operation, int32(status))
}

func authenticateBiometric(reason string) error {
	reasonChars := C.CString(reason)
	defer C.free(unsafe.Pointer(reasonChars))

	var errorChars *C.char
	if C.enpasscli_authenticate_biometric(reasonChars, &errorChars) == 1 {
		return nil
	}
	if errorChars == nil {
		return errors.New("biometric authentication failed")
	}
	defer C.free(unsafe.Pointer(errorChars))
	return fmt.Errorf("biometric authentication failed: %s", C.GoString(errorChars))
}
