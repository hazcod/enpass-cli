package enpass

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/pkg/errors"
)

// NewItemKey returns a fresh 44-byte item key: a 32-byte AES-256 key followed
// by a 12-byte GCM nonce. Enpass stores this blob in item.key and uses it for
// every sensitive field of that item.
func NewItemKey() ([]byte, error) {
	itemKey := make([]byte, 44)
	if _, err := rand.Read(itemKey); err != nil {
		return nil, errors.Wrap(err, "could not generate random item key")
	}

	return itemKey, nil
}

// EncryptValue encrypts a plaintext value using AES-256-GCM.
// Returns the hex-encoded ciphertext and the 44-byte key (32-byte AES key + 12-byte nonce).
// The uuid (without dashes) is used as Additional Authenticated Data (AAD).
func EncryptValue(plaintext string, uuid string) (encryptedValue string, itemKey []byte, err error) {
	itemKey, err = NewItemKey()
	if err != nil {
		return "", nil, err
	}

	encryptedValue, err = EncryptValueWithKey(plaintext, uuid, itemKey)
	if err != nil {
		return "", nil, err
	}

	return encryptedValue, itemKey, nil
}

// EncryptValueWithKey encrypts plaintext with an existing item key.
//
// Enpass keeps one key per item, not one per field: every sensitive row of an
// item is encrypted with the same 32-byte key and 12-byte nonce, which is why
// two fields holding the same value have byte-identical ciphertext. Reusing the
// existing key on update therefore keeps every other sensitive field of the
// item decryptable; generating a new key and storing only the updated field
// would leave the remaining fields encrypted under the old, discarded key.
//
// itemKey must be exactly 44 bytes. The uuid (without dashes) is used as AAD,
// so the ciphertext is bound to the item.
//
// Example: EncryptValueWithKey("hunter2", uuid, existingKey)
func EncryptValueWithKey(plaintext string, uuid string, itemKey []byte) (encryptedValue string, err error) {
	if len(itemKey) != 44 {
		return "", errors.Errorf("item key must be 44 bytes (32 key + 12 nonce), got %d", len(itemKey))
	}

	key := itemKey[:32]
	nonce := itemKey[32:]

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", errors.Wrap(err, "could not create cipher")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "could not create GCM")
	}

	// AAD is the UUID without dashes
	aad, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	if err != nil {
		return "", errors.Wrap(err, "could not decode UUID for AAD")
	}

	// Encrypt (output includes authentication tag)
	ciphertextAndTag := aesgcm.Seal(nil, nonce, []byte(plaintext), aad)

	return hex.EncodeToString(ciphertextAndTag), nil
}
