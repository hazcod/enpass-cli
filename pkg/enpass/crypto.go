package enpass

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/pkg/errors"
)

// EncryptValue encrypts a plaintext value using AES-256-GCM.
// Returns the hex-encoded ciphertext and the 44-byte key (32-byte AES key + 12-byte nonce).
// The uuid (without dashes) is used as Additional Authenticated Data (AAD).
func EncryptValue(plaintext string, uuid string) (encryptedValue string, itemKey []byte, err error) {
	// Generate random 32-byte AES key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", nil, errors.Wrap(err, "could not generate random key")
	}

	// Generate random 12-byte nonce for GCM
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, errors.Wrap(err, "could not generate random nonce")
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, errors.Wrap(err, "could not create cipher")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, errors.Wrap(err, "could not create GCM")
	}

	// AAD is the UUID without dashes
	aad, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	if err != nil {
		return "", nil, errors.Wrap(err, "could not decode UUID for AAD")
	}

	// Encrypt (output includes authentication tag)
	ciphertextAndTag := aesgcm.Seal(nil, nonce, []byte(plaintext), aad)

	// Return hex-encoded ciphertext and key+nonce
	encryptedValue = hex.EncodeToString(ciphertextAndTag)
	itemKey = append(key, nonce...)

	return encryptedValue, itemKey, nil
}
