package pin

import (
	"bytes"
	"os"
	"os/exec"
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
	file, err := getOrCreateStoreFile(vaultPath)
	if err != nil {
		return nil, errors.Wrap(err, "could not create store file")
	}
	if passphrase, err := generatePassphrase(pin, file); err != nil {
		return nil, err
	} else {
		return &SecureStore{
			filePath:            file.Name(),
			passphrase:          passphrase,
			wasReadSuccessfully: false,
		}, nil
	}
}

func getOrCreateStoreFile(vaultPath string) (*os.File, error) {
	dirPath := os.Getenv("XDG_RUNTIME_DIR")
	if dirPath == "" {
		dirPath = os.TempDir()
	}
	fileName := fileNamePref + filepath.Base(vaultPath)
	return os.OpenFile(filepath.Join(dirPath, fileName), os.O_CREATE, fileMode)
}

// this is more obscurity than security but can make trivial attack vectors more difficult
func generatePassphrase(pin string, file *os.File) ([]byte, error) {
	data := []byte(pin)
	lastboot, err := exec.Command("who", "-b").Output()
	if err != nil {
		return nil, errors.Wrap(err, "could not retrieve last boot time")
	}
	data = append(data, bytes.TrimSpace(lastboot)...)
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
