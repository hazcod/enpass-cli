package enpass

import (
	"github.com/sirupsen/logrus"
	"testing"
)

const (
	testPassword = "mymasterpassword"
	vaultPath = "../../test/"
)

func TestVault_Initialize(t *testing.T) {
	vault := Vault{
		Logger: *logrus.New(),
	}
	vault.Logger.SetLevel(logrus.ErrorLevel)
	defer vault.Close()

	if err := vault.Initialize(vaultPath, "", testPassword); err != nil {
		t.Errorf("vault initialization failed: %+v", err)
	}
}

func TestVault_GetEntries(t *testing.T) {
	vault := Vault{
		Logger: *logrus.New(),
	}
	vault.Logger.SetLevel(logrus.ErrorLevel)
	defer vault.Close()

	if err := vault.Initialize(vaultPath, "", testPassword); err != nil {
		t.Errorf("vault initialization failed: %+v", err)
	}

	entries, err := vault.GetEntries("", nil)
	if err != nil {
		t.Errorf("vault get entries failed: %+v", err)
	}

	if len(entries) == 0 {
		t.Error("empty entries returned")
	}
}