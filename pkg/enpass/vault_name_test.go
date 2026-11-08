package enpass

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
)

// Enpass 6 vaults may have an empty or absent vault_name in vault.json.
// This display metadata must not prevent reads after a successful unlock.
func TestVaultReadWithoutName(t *testing.T) {
	for _, name := range []string{"empty", "absent"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			data, err := os.ReadFile(filepath.Join(vaultPath, vaultFileName))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, vaultFileName), data, 0600); err != nil {
				t.Fatal(err)
			}
			info, err := os.ReadFile(filepath.Join(vaultPath, vaultInfoFileName))
			if err != nil {
				t.Fatal(err)
			}
			var metadata map[string]interface{}
			if err := json.Unmarshal(info, &metadata); err != nil {
				t.Fatal(err)
			}
			if name == "empty" {
				metadata["vault_name"] = ""
			} else {
				delete(metadata, "vault_name")
			}
			info, err = json.Marshal(metadata)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, vaultInfoFileName), info, 0600); err != nil {
				t.Fatal(err)
			}

			vault, err := NewVault(dir, logrus.ErrorLevel)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Close()
			if err := vault.Open(&VaultCredentials{Password: testPassword}); err != nil {
				t.Fatal(err)
			}
			for _, read := range []struct {
				name string
				get  func(string, []string) ([]Card, error)
			}{
				{"entries", vault.GetEntries},
				{"fields", vault.GetAllFields},
			} {
				cards, err := read.get("password", nil)
				if err != nil {
					t.Fatalf("read %s after unlock: %v", read.name, err)
				}
				if len(cards) == 0 {
					t.Fatalf("read %s returned no cards", read.name)
				}
				if _, err := cards[0].Decrypt(); err != nil {
					t.Fatalf("decrypt %s: %v", read.name, err)
				}
			}
		})
	}
}

func TestVaultReadBeforeOpen(t *testing.T) {
	vault, err := NewVault(vaultPath, logrus.ErrorLevel)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	if _, err := vault.GetEntries("password", nil); err == nil {
		t.Fatal("GetEntries accepted an unopened vault")
	}
	if _, err := vault.GetAllFields("password", nil); err == nil {
		t.Fatal("GetAllFields accepted an unopened vault")
	}
}
