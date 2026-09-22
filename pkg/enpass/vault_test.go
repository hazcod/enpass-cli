package enpass

import (
	"testing"

	"github.com/sirupsen/logrus"
)

const (
	testPassword = "absolutely-No-clue"
	vaultPath    = "../../test/"
)

func TestVault_Initialize(t *testing.T) {
	vault, err := NewVault(vaultPath, logrus.ErrorLevel)
	if err != nil {
		t.Errorf("vault initialization failed: %+v", err)
	}
	defer vault.Close()
	credentials := &VaultCredentials{Password: testPassword}
	if err := vault.Open(credentials); err != nil {
		t.Errorf("opening vault failed: %+v", err)
	}
}

func TestVault_GetEntries(t *testing.T) {
	vault, err := NewVault(vaultPath, logrus.ErrorLevel)
	if err != nil {
		t.Errorf("vault initialization failed: %+v", err)
	}
	defer vault.Close()
	credentials := &VaultCredentials{Password: testPassword}
	if err := vault.Open(credentials); err != nil {
		t.Errorf("opening vault failed: %+v", err)
	}

	Assert_GetEntries(t, vault, nil, 1)
}

func TestVault_GetEntries_Filter_OR(t *testing.T) {
	vault, err := NewVault(vaultPath, logrus.ErrorLevel)
	if err != nil {
		t.Errorf("vault initialization failed: %+v", err)
	}
	defer vault.Close()
	credentials := &VaultCredentials{Password: testPassword}
	if err := vault.Open(credentials); err != nil {
		t.Errorf("opening vault failed: %+v", err)
	}

	vault.FilterAnd = false

	Assert_GetEntries(t, vault, []string{"Whatever"}, 1)              // matches title
	Assert_GetEntries(t, vault, []string{"johndoe@whatever.com"}, 1)  // matches subtitle
	Assert_GetEntries(t, vault, []string{"inexistent"}, 0)            // matches nothing
	Assert_GetEntries(t, vault, []string{"Whatever", "johndoe"}, 1)
	Assert_GetEntries(t, vault, []string{"Whatever", "inexistent"}, 1)
	Assert_GetEntries(t, vault, []string{"inexistent", "alsoinexistent"}, 0)
}

func TestVault_GetEntries_Filter_AND(t *testing.T) {
	vault, err := NewVault(vaultPath, logrus.ErrorLevel)
	if err != nil {
		t.Errorf("vault initialization failed: %+v", err)
	}
	defer vault.Close()
	credentials := &VaultCredentials{Password: testPassword}
	if err := vault.Open(credentials); err != nil {
		t.Errorf("opening vault failed: %+v", err)
	}

	vault.FilterAnd = true

	Assert_GetEntries(t, vault, []string{"Whatever"}, 1)              // matches title
	Assert_GetEntries(t, vault, []string{"johndoe@whatever.com"}, 1)  // matches subtitle
	Assert_GetEntries(t, vault, []string{"inexistent"}, 0)            // matches nothing
	Assert_GetEntries(t, vault, []string{"Whatever", "johndoe"}, 1)
	Assert_GetEntries(t, vault, []string{"Whatever", "inexistent"}, 0)
	Assert_GetEntries(t, vault, []string{"inexistent", "alsoinexistent"}, 0)
}

func TestVault_GetEntries_Filter_Exact(t *testing.T) {
	vault, err := NewVault(vaultPath, logrus.ErrorLevel)
	if err != nil {
		t.Errorf("vault initialization failed: %+v", err)
	}
	defer vault.Close()
	credentials := &VaultCredentials{Password: testPassword}
	if err := vault.Open(credentials); err != nil {
		t.Errorf("opening vault failed: %+v", err)
	}

	vault.FilterExact = true

	Assert_GetEntries(t, vault, []string{"Whatever"}, 1)              // matches full title
	Assert_GetEntries(t, vault, []string{"whatever"}, 1)              // case-insensitive
	Assert_GetEntries(t, vault, []string{"What"}, 0)                  // substring no longer matches
	Assert_GetEntries(t, vault, []string{"johndoe@whatever.com"}, 1)  // matches full subtitle
	Assert_GetEntries(t, vault, []string{"johndoe"}, 0)               // subtitle substring no longer matches
	Assert_GetEntries(t, vault, []string{"What", "Whatever"}, 1)      // OR: one exact match suffices
}

func TestVault_GetEntries_Filter_Fields(t *testing.T) {
	vault, err := NewVault(vaultPath, logrus.ErrorLevel)
	if err != nil {
		t.Errorf("vault initialization failed: %+v", err)
	}
	defer vault.Close()
	credentials := &VaultCredentials{Password: testPassword}
	if err := vault.Open(credentials); err != nil {
		t.Errorf("opening vault failed: %+v", err)
	}

	vault.FilterAnd = false

	vault.FilterFields = []string{"title"}
	Assert_GetEntries(t, vault, []string{"Whatever"}, 1)              // matches title
	Assert_GetEntries(t, vault, []string{"johndoe@whatever.com"}, 0)  // matches subtitle
	Assert_GetEntries(t, vault, []string{"Whatever", "johndoe"}, 1)

	vault.FilterFields = []string{"subtitle"}
	Assert_GetEntries(t, vault, []string{"Whatever"}, 1)              // subtitle contains "whatever" in domain
	Assert_GetEntries(t, vault, []string{"johndoe@whatever.com"}, 1)  // matches subtitle exactly
	Assert_GetEntries(t, vault, []string{"johndoe"}, 1)               // matches subtitle username part

	vault.FilterFields = []string{"title", "subtitle"}
	Assert_GetEntries(t, vault, []string{"Whatever"}, 1)              // matches title
	Assert_GetEntries(t, vault, []string{"johndoe@whatever.com"}, 1)  // matches subtitle
	Assert_GetEntries(t, vault, []string{"Whatever", "johndoe"}, 1)
}

func Assert_GetEntries(t *testing.T, vault *Vault, filters []string, expectedCount int) {
	entries, err := vault.GetEntries("password", filters)
	if err != nil {
		t.Errorf("vault get entries failed: %+v", err)
	} else if len(entries) != expectedCount {
		t.Error("wrong number of entries returned")
	}
}
