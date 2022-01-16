package unlock

import (
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	fileNamePref = "enpasscli-"
	fileMode     = 0600
)

type SecureStore struct {
	logger              logrus.Logger
	file                *os.File
	passphrase          []byte
	kdfIterCount        int
	wasReadSuccessfully bool
}

func NewSecureStore(name string, logLevel logrus.Level) (*SecureStore, error) {
	store := SecureStore{logger: *logrus.New()}
	store.logger.SetLevel(logLevel)
	store.logger.Debug("loading store file")
	var err error
	store.file, err = store.getStoreFile(name)
	return &store, errors.Wrap(err, "could not load store file")
}

func (store *SecureStore) getStoreFile(name string) (*os.File, error) {
	var storeFile *os.File
	var err error
	storeFileName := fileNamePref + name
	for _, tempDir := range [...]string{
		os.Getenv("TMPDIR"),
		os.Getenv("XDG_RUNTIME_DIR"),
		"/dev/shm",
		os.TempDir(),
	} {
		if tempDir == "" {
			continue
		}
		store.logger.WithField("tempDir", tempDir).Debug("trying store directory")
		storeFilePath := filepath.Join(tempDir, storeFileName)
		storeFile, err = os.OpenFile(storeFilePath, os.O_CREATE, fileMode)
		if err == nil {
			break
		}
		store.logger.WithError(err).Debug("skipping store directory")
	}
	return storeFile, err
}

func (store *SecureStore) GeneratePassphrase(pin string, pepper string, kdfIterCount int) error {
	store.logger.WithField("kdfIterCount", kdfIterCount).Debug("generating store passphrase from pin")
	store.kdfIterCount = kdfIterCount
	data := append([]byte(pin), []byte(pepper)...)
	store.passphrase = sha256sum(data)
	return nil
}

func (store *SecureStore) Read() ([]byte, error) {
	if store.passphrase == nil {
		return nil, errors.New("empty store passphrase")
	}
	store.logger.Debug("reading store data")
	data, _ := os.ReadFile(store.file.Name())
	if len(data) == 0 {
		return nil, nil // nothing to read
	}
	store.logger.Debug("decrypting store data")
	ts := time.Now().UnixNano()
	dbKey, err := decrypt(store.passphrase, data, store.kdfIterCount)
	ts = time.Now().UnixNano() - ts
	store.logger.Trace("decrypted in ", ts/int64(time.Millisecond), "ms")
	if err != nil {
		return nil, err
	}
	store.wasReadSuccessfully = (len(dbKey) > 0)
	return dbKey, nil
}

func (store *SecureStore) Write(dbKey []byte) error {
	if store.wasReadSuccessfully {
		return nil // no need to overwrite the file if read was already successful
	}
	if store.passphrase == nil {
		return errors.New("empty store passphrase")
	}
	store.logger.Debug("encrypting store data")
	data, err := encrypt(store.passphrase, dbKey, store.kdfIterCount)
	if err != nil {
		return err
	}
	store.logger.Debug("writing store data")
	return os.WriteFile(store.file.Name(), data, fileMode)
}

func (store *SecureStore) Clean() error {
	store.wasReadSuccessfully = false
	return os.Remove(store.file.Name())
}
