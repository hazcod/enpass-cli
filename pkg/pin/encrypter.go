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

func deriveKey(passphrase string, salt []byte, kdfIterCount int) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, saltLength)
		rand.Read(salt) // Salt http://www.ietf.org/rfc/rfc2898.txt
	}
	if kdfIterCount < minKdfIterCount {
		kdfIterCount = minKdfIterCount
	}
	return pbkdf2.Key([]byte(passphrase), salt, kdfIterCount, sha256.Size, sha256.New), salt
}

func createCipherGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func encrypt(passphrase string, plaintext []byte, kdfIterCount int) (string, error) {
	key, salt := deriveKey(passphrase, nil, kdfIterCount)
	iv := make([]byte, 12)
	rand.Read(iv) // Section 8.2 http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	aesgcm, err := createCipherGCM(key)
	if err != nil {
		return "", err
	}
	data := aesgcm.Seal(nil, iv, plaintext, nil)
	return hex.EncodeToString(salt) + "-" + hex.EncodeToString(iv) + "-" + hex.EncodeToString(data), nil
}

func decrypt(passphrase, ciphertext string, kdfIterCount int) ([]byte, error) {
	arr := strings.Split(ciphertext, "-")
	salt, _ := hex.DecodeString(arr[0])
	iv, _ := hex.DecodeString(arr[1])
	data, _ := hex.DecodeString(arr[2])
	key, _ := deriveKey(passphrase, salt, kdfIterCount)
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
