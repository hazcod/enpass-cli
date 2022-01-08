package pin

import (
	"errors"
	"os"
	"path/filepath"
)

const (
	storeFileName = "enpasscli.mpw"
	kdfIterCount  = 100000
)

type SecureStore struct {
	filePath            string
	passphrase          string
	wasReadSuccessfully bool
}

func NewSecureStore(pin string) (*SecureStore, error) {
	dirPath := os.Getenv("XDG_RUNTIME_DIR")
	if dirPath == "" {
		dirPath = os.TempDir()
	}
	// TODO check dir read/writeablility ?
	if passphrase, err := generatePassphrase(pin); err != nil {
		return nil, err
	} else {
		return &SecureStore{
			filePath:            filepath.Join(dirPath, storeFileName),
			passphrase:          passphrase,
			wasReadSuccessfully: false,
		}, nil
	}
}

func generatePassphrase(pin string) (string, error) {
	if pin == "" {
		return "", errors.New("PIN not set")
	}
	// TODO check PIN length / quality
	// TODO calc passphrase
	return pin, nil
}

func (store *SecureStore) Read() ([]byte, error) {
	if store.passphrase == "" {
		return nil, errors.New("empty store passphrase")
	}
	data, _ := os.ReadFile(store.filePath)
	if data == nil {
		return nil, nil // nothing to read
	}
	dbKey, err := decrypt(store.passphrase, string(data), kdfIterCount)
	if err != nil {
		return nil, err
	}
	store.wasReadSuccessfully = (dbKey != nil)
	return dbKey, nil
}

func (store *SecureStore) Write(dbKey []byte) error {
	if store.wasReadSuccessfully {
		return nil // no need to overwrite the file if read was already successful
	}
	if store.passphrase == "" {
		return errors.New("empty store passphrase")
	}
	data, err := encrypt(store.passphrase, dbKey, kdfIterCount)
	if err != nil {
		return err
	}
	return os.WriteFile(store.filePath, []byte(data), 0600)
}

func (store *SecureStore) Clear() error {
	store.wasReadSuccessfully = false
	return os.Remove(store.filePath)
}
