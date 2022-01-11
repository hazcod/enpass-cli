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
	passphrase, err := generatePassphrase(pin)
	if err != nil {
		return nil, err
	}
	file, err := openStore(vaultPath)
	if err != nil {
		return nil, errors.Wrap(err, "could not open store")
	}
	return &SecureStore{
		filePath:   file.Name(),
		passphrase: passphrase,
	}, nil
}

func openStore(vaultPath string) (*os.File, error) {
	var storeFile *os.File
	var err error
	vaultPath, err = filepath.EvalSymlinks(vaultPath)
	storeFileName := fileNamePref + filepath.Base(vaultPath)
	for _, tempDir := range []string{
		os.Getenv("TMPDIR"),
		os.Getenv("XDG_RUNTIME_DIR"),
		"/dev/shm",
		os.TempDir(),
	} {
		if tempDir == "" {
			continue
		}
		storeFilePath := filepath.Join(tempDir, storeFileName)
		storeFile, err = os.OpenFile(storeFilePath, os.O_CREATE, fileMode)
		if err == nil {
			break
		}
	}
	return storeFile, err
}

func generatePassphrase(pin string) ([]byte, error) {
	if len(pin) < minPinLength {
		return nil, errors.New("PIN too short")
	}
	pepper := []byte(os.Getenv("PIN_PEPPER"))
	data := append([]byte(pin), pepper...)
	return sha256sum(data), nil
}

func (store *SecureStore) Read() ([]byte, error) {
	if store.passphrase == nil {
		return nil, errors.New("empty store passphrase")
	}
	data, _ := os.ReadFile(store.filePath)
	if data == nil || len(data) == 0 {
		return nil, nil // nothing to read
	}
	dbKey, err := decrypt(store.passphrase, data, kdfIterCount)
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
	return os.WriteFile(store.filePath, data, fileMode)
}

func (store *SecureStore) Clear() error {
	store.wasReadSuccessfully = false
	return os.Remove(store.filePath)
}
