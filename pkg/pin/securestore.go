package pin

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

const (
	fileNamePref = "enpasscli-"
	fileMode     = 0600
	kdfIterCount = 100000
	minPinLength = 8
)

type SecureStore struct {
	filePath            string
	passphrase          []byte
	wasReadSuccessfully bool
}

func NewSecureStore(pin string, vaultPath string) (*SecureStore, error) {
	if len(pin) < minPinLength {
		return nil, errors.New("PIN too short")
	}
	vaultPath, _ = filepath.EvalSymlinks(vaultPath)
	file, err := getOrCreateStoreFile(vaultPath)
	if err != nil {
		return nil, errors.Wrap(err, "could not create store file")
	}
	if passphrase, err := generatePassphrase(pin, vaultPath); err != nil {
		return nil, err
	} else {
		return &SecureStore{
			filePath:            file.Name(),
			passphrase:          passphrase,
			wasReadSuccessfully: false,
		}, nil
	}
}

func getTempDir() string {
	tempDir := os.Getenv("TMPDIR")
	if tempDir == "" {
		tempDir = os.Getenv("XDG_RUNTIME_DIR")
	}
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	return tempDir
}

func getOrCreateStoreFile(vaultPath string) (*os.File, error) {
	fileName := fileNamePref + filepath.Base(vaultPath)
	return os.OpenFile(filepath.Join(getTempDir(), fileName), os.O_CREATE, fileMode)
}

// this is more obscurity than security but can make brute force less trivial
func generatePassphrase(pin string, vaultPath string) ([]byte, error) {
	vaultPath, err := filepath.Abs(vaultPath)
	data := append([]byte(pin), []byte(vaultPath)...)
	return sha256sum(data), err
}

func (store *SecureStore) Read() ([]byte, error) {
	if store.passphrase == nil {
		return nil, errors.New("empty store passphrase")
	}
	data, _ := os.ReadFile(store.filePath)
	if data == nil || len(data) == 0 {
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
	if store.passphrase == nil {
		return errors.New("empty store passphrase")
	}
	data, err := encrypt(store.passphrase, dbKey, kdfIterCount)
	if err != nil {
		return err
	}
	return os.WriteFile(store.filePath, []byte(data), fileMode)
}

func (store *SecureStore) Clear() error {
	store.wasReadSuccessfully = false
	return os.Remove(store.filePath)
}
