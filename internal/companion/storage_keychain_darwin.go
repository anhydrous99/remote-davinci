//go:build darwin && cgo

package companion

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static CFMutableDictionaryRef rd_keychain_query(const char *service, const char *account) {
	CFStringRef service_value = CFStringCreateWithCString(
		kCFAllocatorDefault, service, kCFStringEncodingUTF8);
	CFStringRef account_value = CFStringCreateWithCString(
		kCFAllocatorDefault, account, kCFStringEncodingUTF8);
	if (service_value == NULL || account_value == NULL) {
		if (service_value != NULL) CFRelease(service_value);
		if (account_value != NULL) CFRelease(account_value);
		return NULL;
	}
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks);
	// ponytail: a bare helper uses the login Keychain; switch to the data
	// protection Keychain only with app-like packaging and entitlements.
	if (query != NULL) {
		CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
		CFDictionarySetValue(query, kSecAttrService, service_value);
		CFDictionarySetValue(query, kSecAttrAccount, account_value);
	}
	CFRelease(service_value);
	CFRelease(account_value);
	return query;
}

static OSStatus rd_keychain_load(
	const char *service, const char *account, void **out_bytes, CFIndex *out_length) {
	*out_bytes = NULL;
	*out_length = 0;
	CFMutableDictionaryRef query = rd_keychain_query(service, account);
	if (query == NULL) return errSecAllocate;
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	if (status != errSecSuccess) return status;
	if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
		if (result != NULL) CFRelease(result);
		return errSecDecode;
	}
	CFDataRef data = (CFDataRef)result;
	CFIndex length = CFDataGetLength(data);
	void *copy = length == 0 ? NULL : malloc((size_t)length);
	if (length != 0 && copy == NULL) {
		CFRelease(result);
		return errSecAllocate;
	}
	if (length != 0) memcpy(copy, CFDataGetBytePtr(data), (size_t)length);
	CFRelease(result);
	*out_bytes = copy;
	*out_length = length;
	return errSecSuccess;
}

static OSStatus rd_keychain_save(
	const char *service, const char *account, const void *bytes, CFIndex length) {
	CFMutableDictionaryRef query = rd_keychain_query(service, account);
	if (query == NULL) return errSecAllocate;
	CFDataRef data = CFDataCreate(kCFAllocatorDefault, bytes, length);
	if (data == NULL) {
		CFRelease(query);
		return errSecAllocate;
	}
	CFMutableDictionaryRef update = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks);
	if (update == NULL) {
		CFRelease(data);
		CFRelease(query);
		return errSecAllocate;
	}
	CFDictionarySetValue(update, kSecValueData, data);
	OSStatus status = SecItemUpdate(query, update);
	if (status == errSecItemNotFound) {
		CFMutableDictionaryRef item = CFDictionaryCreateMutableCopy(
			kCFAllocatorDefault, 0, query);
		if (item == NULL) {
			status = errSecAllocate;
		} else {
			CFDictionarySetValue(item, kSecValueData, data);
			status = SecItemAdd(item, NULL);
			CFRelease(item);
			if (status == errSecDuplicateItem) status = SecItemUpdate(query, update);
		}
	}
	CFRelease(update);
	CFRelease(data);
	CFRelease(query);
	return status;
}

static OSStatus rd_keychain_delete(const char *service, const char *account) {
	CFMutableDictionaryRef query = rd_keychain_query(service, account);
	if (query == NULL) return errSecAllocate;
	OSStatus status = SecItemDelete(query);
	CFRelease(query);
	return status;
}
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

func (store KeychainConfigStore) Load() (Config, error) {
	service, account, err := store.identifiers()
	if err != nil {
		return Config{}, err
	}
	serviceCString, accountCString := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(serviceCString))
	defer C.free(unsafe.Pointer(accountCString))
	var bytes unsafe.Pointer
	var length C.CFIndex
	status := C.rd_keychain_load(serviceCString, accountCString, &bytes, &length)
	if status == C.errSecItemNotFound {
		return Config{}, os.ErrNotExist
	}
	if status != C.errSecSuccess {
		return Config{}, keychainStatusError("load", status)
	}
	defer C.free(bytes)
	if length <= 0 || length > C.CFIndex(maxStoredConfigBytes) {
		return Config{}, fmt.Errorf("invalid companion configuration")
	}
	return decodeStoredConfig(C.GoBytes(bytes, C.int(length)))
}

func (store KeychainConfigStore) Save(config Config) error {
	service, account, err := store.identifiers()
	if err != nil {
		return err
	}
	data, err := encodeStoredConfig(config)
	if err != nil {
		return err
	}
	serviceCString, accountCString := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(serviceCString))
	defer C.free(unsafe.Pointer(accountCString))
	bytes := C.CBytes(data)
	defer C.free(bytes)
	status := C.rd_keychain_save(serviceCString, accountCString, bytes, C.CFIndex(len(data)))
	if status != C.errSecSuccess {
		return keychainStatusError("save", status)
	}
	return nil
}

func (store KeychainConfigStore) Delete() error {
	service, account, err := store.identifiers()
	if err != nil {
		return err
	}
	serviceCString, accountCString := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(serviceCString))
	defer C.free(unsafe.Pointer(accountCString))
	status := C.rd_keychain_delete(serviceCString, accountCString)
	if status == C.errSecSuccess || status == C.errSecItemNotFound {
		return nil
	}
	return keychainStatusError("delete", status)
}

func keychainStatusError(operation string, status C.OSStatus) error {
	return fmt.Errorf("Keychain %s failed (status %d)", operation, int32(status))
}
