package unlock

// based on https://gist.github.com/tscholl2/dc7dc15dc132ea70a98e8542fefffa28#file-aes-go

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

const (
	bytesIV         = 12
	bytesSalt       = 16
	minKdfIterCount = 10000
)

func generateRandom(bytes int) ([]byte, error) {
	generated := make([]byte, bytes)
	_, err := rand.Read(generated)
	return generated, err
}

func sha256sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func deriveKey(passphrase []byte, salt []byte, kdfIterCount int) []byte {
	if kdfIterCount < minKdfIterCount {
		kdfIterCount = minKdfIterCount
	}
	return pbkdf2.Key(passphrase, salt, kdfIterCount, sha256.Size, sha256.New)
}

func createCipherGCM(key []byte) (cipher.AEAD, error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(cipherBlock)
}

func encrypt(passphrase []byte, plaintext []byte, kdfIterCount int) ([]byte, error) {
	salt, err := generateRandom(bytesSalt)
	if err != nil {
		return nil, err
	}
	key := deriveKey(passphrase, salt, kdfIterCount)
	aesgcm, err := createCipherGCM(key)
	if err != nil {
		return nil, err
	}
	iv, err := generateRandom(bytesIV)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)
	data := append(ciphertext, salt...)
	data = append(iv, data...)
	return data, nil
}

func decrypt(passphrase []byte, data []byte, kdfIterCount int) ([]byte, error) {
	saltIdx := len(data) - bytesSalt
	iv := data[:bytesIV]
	ciphertext := data[bytesIV:saltIdx]
	salt := data[saltIdx:]
	key := deriveKey(passphrase, salt, kdfIterCount)
	aesgcm, err := createCipherGCM(key)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, iv, ciphertext, nil)
}
