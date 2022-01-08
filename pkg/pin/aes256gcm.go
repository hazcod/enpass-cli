package pin

// based on https://gist.github.com/tscholl2/dc7dc15dc132ea70a98e8542fefffa28#file-aes-go

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltLength      = 16
	minKdfIterCount = 10000
)

func sha256sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func generateSalt() []byte {
	salt := make([]byte, saltLength)
	rand.Read(salt) // Salt http://www.ietf.org/rfc/rfc2898.txt
	return salt
}

func deriveKey(passphrase []byte, salt []byte, kdfIterCount int) []byte {
	if kdfIterCount < minKdfIterCount {
		kdfIterCount = minKdfIterCount
	}
	return pbkdf2.Key(passphrase, salt, kdfIterCount, sha256.Size, sha256.New)
}

func createCipherGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func encrypt(passphrase []byte, plaintext []byte, kdfIterCount int) (string, error) {
	salt := generateSalt()
	key := deriveKey(passphrase, salt, kdfIterCount)
	iv := make([]byte, 12)
	rand.Read(iv) // Section 8.2 http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	aesgcm, err := createCipherGCM(key)
	if err != nil {
		return "", err
	}
	data := aesgcm.Seal(nil, iv, plaintext, nil)
	return hex.EncodeToString(salt) + "-" + hex.EncodeToString(iv) + "-" + hex.EncodeToString(data), nil
}

func decrypt(passphrase []byte, ciphertext string, kdfIterCount int) ([]byte, error) {
	arr := strings.Split(ciphertext, "-")
	salt, _ := hex.DecodeString(arr[0])
	iv, _ := hex.DecodeString(arr[1])
	data, _ := hex.DecodeString(arr[2])
	key := deriveKey(passphrase, salt, kdfIterCount)
	aesgcm, err := createCipherGCM(key)
	if err != nil {
		return nil, err
	}
	data, err = aesgcm.Open(nil, iv, data, nil)
	if err != nil {
		return nil, err
	}
	return data, nil
}
