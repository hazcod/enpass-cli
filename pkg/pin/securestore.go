package pin

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	fileNamePref = "enpasscli-"
	fileMode     = 0600
	kdfIterCount = 100000
	minPinLength = 8
)

type SecureStore struct {
	Logger              logrus.Logger
	file                *os.File
	passphrase          []byte
	wasReadSuccessfully bool
}

func (store *SecureStore) Initialize(pin string, vaultPath string) error {
	var err error
	store.Logger.Debug("generating store passphrase from pin")
	store.passphrase, err = store.generatePassphrase(pin)
	if err != nil {
		return err
	}
	store.Logger.Debug("opening store")
	store.file, err = store.open(vaultPath)
	return errors.Wrap(err, "could not open store")
}

func (store *SecureStore) open(vaultPath string) (*os.File, error) {
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
		store.Logger.WithField("tempDir", tempDir).Debug("trying store directory")
		storeFilePath := filepath.Join(tempDir, storeFileName)
		storeFile, err = os.OpenFile(storeFilePath, os.O_CREATE, fileMode)
		if err == nil {
			break
		}
		store.Logger.WithError(err).Debug("skipping store directory")
	}
	return storeFile, err
}

func (store *SecureStore) generatePassphrase(pin string) ([]byte, error) {
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
	store.Logger.Debug("reading store")
	data, _ := os.ReadFile(store.file.Name())
	if data == nil || len(data) == 0 {
		return nil, nil // nothing to read
	}
	store.Logger.Debug("decrypting store data")
	dbKey, err := decrypt(store.passphrase, data, kdfIterCount)
	if err != nil {
		return nil, err
	}
	store.wasReadSuccessfully = (dbKey != nil && len(dbKey) > 0)
	return dbKey, nil
}

func (store *SecureStore) Write(dbKey []byte) error {
	if store.wasReadSuccessfully {
		return nil // no need to overwrite the file if read was already successful
	}
	if store.passphrase == nil {
		return errors.New("empty store passphrase")
	}
	store.Logger.Debug("encrypting store data")
	data, err := encrypt(store.passphrase, dbKey, kdfIterCount)
	if err != nil {
		return err
	}
	store.Logger.Debug("writing store")
	return os.WriteFile(store.file.Name(), data, fileMode)
}

func (store *SecureStore) Clear() error {
	store.wasReadSuccessfully = false
	return os.Remove(store.file.Name())
}
