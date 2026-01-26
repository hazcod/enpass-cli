package enpass

import (
	"testing"
)

func TestEncryptValue(t *testing.T) {
	plaintext := "mysecretpassword"
	uuid := "a2ec30c0-aeed-41f7-aed7-cc50e69ff506"

	encryptedValue, itemKey, err := EncryptValue(plaintext, uuid)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if len(encryptedValue) == 0 {
		t.Error("encrypted value is empty")
	}

	if len(itemKey) != 44 {
		t.Errorf("itemKey should be 44 bytes (32 key + 12 nonce), got %d", len(itemKey))
	}

	// Verify we can decrypt it back using Card.Decrypt()
	card := &Card{
		UUID:    uuid,
		Type:    "password",
		value:   encryptedValue,
		itemKey: itemKey,
	}

	decrypted, err := card.Decrypt()
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("roundtrip failed: expected %q, got %q", plaintext, decrypted)
	}
}

func TestEncryptValueDifferentKeys(t *testing.T) {
	plaintext := "mysecretpassword"
	uuid := "a2ec30c0-aeed-41f7-aed7-cc50e69ff506"

	value1, key1, _ := EncryptValue(plaintext, uuid)
	value2, key2, _ := EncryptValue(plaintext, uuid)

	// Each encryption should produce different ciphertext (different random key/nonce)
	if value1 == value2 {
		t.Error("encryptions should produce different ciphertext")
	}

	if string(key1) == string(key2) {
		t.Error("encryptions should use different keys")
	}
}
