package enpass

import (
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// EntryData holds the data for creating or updating an entry
type EntryData struct {
	Title    string
	Username string
	Password string
	URL      string
	Notes    string
	Category string
}

// CreateEntry creates a new password entry in the vault
func (v *Vault) CreateEntry(entry *EntryData) (string, error) {
	if v.db == nil {
		return "", errors.New("vault is not initialized")
	}

	if entry.Title == "" {
		return "", errors.New("title is required")
	}

	// Generate UUID
	entryUUID := uuid.New().String()
	now := time.Now().Unix()

	// Set defaults
	category := entry.Category
	if category == "" {
		category = "Login"
	}

	// Start transaction
	tx, err := v.db.Begin()
	if err != nil {
		return "", errors.Wrap(err, "could not begin transaction")
	}
	defer tx.Rollback()

	// Insert into item table
	_, err = tx.Exec(`
		INSERT INTO item (
			uuid, type, created_at, field_updated_at, title, subtitle,
			note, trashed, deleted, category, icon, last_used
		) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?)
	`, entryUUID, "password", now, now, entry.Title, entry.Username,
		entry.Notes, category, "card_password", now)
	if err != nil {
		return "", errors.Wrap(err, "could not insert item")
	}

	// Encrypt and insert password field
	if entry.Password != "" {
		encryptedValue, itemKey, err := EncryptValue(entry.Password, entryUUID)
		if err != nil {
			return "", errors.Wrap(err, "could not encrypt password")
		}

		_, err = tx.Exec(`
			INSERT INTO itemfield (
				item_uuid, label, value, key, deleted, sensitive, type
			) VALUES (?, ?, ?, ?, 0, 1, ?)
		`, entryUUID, "password", encryptedValue, itemKey, "password")
		if err != nil {
			return "", errors.Wrap(err, "could not insert password field")
		}
	}

	// Insert username field (not encrypted)
	if entry.Username != "" {
		_, err = tx.Exec(`
			INSERT INTO itemfield (
				item_uuid, label, value, key, deleted, sensitive, type
			) VALUES (?, ?, ?, NULL, 0, 0, ?)
		`, entryUUID, "username", entry.Username, "username")
		if err != nil {
			return "", errors.Wrap(err, "could not insert username field")
		}
	}

	// Insert URL field (not encrypted)
	if entry.URL != "" {
		_, err = tx.Exec(`
			INSERT INTO itemfield (
				item_uuid, label, value, key, deleted, sensitive, type
			) VALUES (?, ?, ?, NULL, 0, 0, ?)
		`, entryUUID, "url", entry.URL, "url")
		if err != nil {
			return "", errors.Wrap(err, "could not insert URL field")
		}
	}

	if err := tx.Commit(); err != nil {
		return "", errors.Wrap(err, "could not commit transaction")
	}

	v.logger.WithField("uuid", entryUUID).Debug("created entry")
	return entryUUID, nil
}

// UpdateEntry updates an existing entry in the vault
func (v *Vault) UpdateEntry(entryUUID string, updates *EntryData) error {
	if v.db == nil {
		return errors.New("vault is not initialized")
	}

	now := time.Now().Unix()

	// Start transaction
	tx, err := v.db.Begin()
	if err != nil {
		return errors.Wrap(err, "could not begin transaction")
	}
	defer tx.Rollback()

	// Update item table if title, notes, or category changed
	if updates.Title != "" || updates.Notes != "" || updates.Category != "" {
		query := "UPDATE item SET field_updated_at = ?"
		args := []interface{}{now}

		if updates.Title != "" {
			query += ", title = ?"
			args = append(args, updates.Title)
		}
		if updates.Notes != "" {
			query += ", note = ?"
			args = append(args, updates.Notes)
		}
		if updates.Category != "" {
			query += ", category = ?"
			args = append(args, updates.Category)
		}

		query += " WHERE uuid = ?"
		args = append(args, entryUUID)

		_, err = tx.Exec(query, args...)
		if err != nil {
			return errors.Wrap(err, "could not update item")
		}
	}

	// Update username in item.subtitle and itemfield
	if updates.Username != "" {
		_, err = tx.Exec("UPDATE item SET subtitle = ?, field_updated_at = ? WHERE uuid = ?",
			updates.Username, now, entryUUID)
		if err != nil {
			return errors.Wrap(err, "could not update subtitle")
		}

		// Update or insert username field
		result, err := tx.Exec("UPDATE itemfield SET value = ? WHERE item_uuid = ? AND label = ?",
			updates.Username, entryUUID, "username")
		if err != nil {
			return errors.Wrap(err, "could not update username field")
		}
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			_, err = tx.Exec(`
				INSERT INTO itemfield (item_uuid, label, value, key, deleted, sensitive, type)
				VALUES (?, ?, ?, NULL, 0, 0, ?)
			`, entryUUID, "username", updates.Username, "username")
			if err != nil {
				return errors.Wrap(err, "could not insert username field")
			}
		}
	}

	// Update password (encrypted)
	if updates.Password != "" {
		encryptedValue, itemKey, err := EncryptValue(updates.Password, entryUUID)
		if err != nil {
			return errors.Wrap(err, "could not encrypt password")
		}

		result, err := tx.Exec("UPDATE itemfield SET value = ?, key = ? WHERE item_uuid = ? AND label = ?",
			encryptedValue, itemKey, entryUUID, "password")
		if err != nil {
			return errors.Wrap(err, "could not update password field")
		}
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			_, err = tx.Exec(`
				INSERT INTO itemfield (item_uuid, label, value, key, deleted, sensitive, type)
				VALUES (?, ?, ?, ?, 0, 1, ?)
			`, entryUUID, "password", encryptedValue, itemKey, "password")
			if err != nil {
				return errors.Wrap(err, "could not insert password field")
			}
		}
	}

	// Update URL
	if updates.URL != "" {
		result, err := tx.Exec("UPDATE itemfield SET value = ? WHERE item_uuid = ? AND label = ?",
			updates.URL, entryUUID, "url")
		if err != nil {
			return errors.Wrap(err, "could not update URL field")
		}
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			_, err = tx.Exec(`
				INSERT INTO itemfield (item_uuid, label, value, key, deleted, sensitive, type)
				VALUES (?, ?, ?, NULL, 0, 0, ?)
			`, entryUUID, "url", updates.URL, "url")
			if err != nil {
				return errors.Wrap(err, "could not insert URL field")
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "could not commit transaction")
	}

	v.logger.WithField("uuid", entryUUID).Debug("updated entry")
	return nil
}

// TrashEntry moves an entry to the trash
func (v *Vault) TrashEntry(entryUUID string) error {
	if v.db == nil {
		return errors.New("vault is not initialized")
	}

	now := time.Now().Unix()
	result, err := v.db.Exec("UPDATE item SET trashed = 1, field_updated_at = ? WHERE uuid = ?", now, entryUUID)
	if err != nil {
		return errors.Wrap(err, "could not trash entry")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("entry not found")
	}

	v.logger.WithField("uuid", entryUUID).Debug("trashed entry")
	return nil
}

// RestoreEntry restores an entry from the trash
func (v *Vault) RestoreEntry(entryUUID string) error {
	if v.db == nil {
		return errors.New("vault is not initialized")
	}

	now := time.Now().Unix()
	result, err := v.db.Exec("UPDATE item SET trashed = 0, field_updated_at = ? WHERE uuid = ?", now, entryUUID)
	if err != nil {
		return errors.Wrap(err, "could not restore entry")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("entry not found")
	}

	v.logger.WithField("uuid", entryUUID).Debug("restored entry")
	return nil
}

// DeleteEntry permanently deletes an entry from the vault
func (v *Vault) DeleteEntry(entryUUID string) error {
	if v.db == nil {
		return errors.New("vault is not initialized")
	}

	// Start transaction
	tx, err := v.db.Begin()
	if err != nil {
		return errors.Wrap(err, "could not begin transaction")
	}
	defer tx.Rollback()

	// Delete from itemfield first (foreign key constraint)
	_, err = tx.Exec("DELETE FROM itemfield WHERE item_uuid = ?", entryUUID)
	if err != nil {
		return errors.Wrap(err, "could not delete item fields")
	}

	// Delete from item
	result, err := tx.Exec("DELETE FROM item WHERE uuid = ?", entryUUID)
	if err != nil {
		return errors.Wrap(err, "could not delete item")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("entry not found")
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "could not commit transaction")
	}

	v.logger.WithField("uuid", entryUUID).Debug("deleted entry")
	return nil
}

// GetEntryByUUID retrieves a single entry by its UUID (including trashed)
func (v *Vault) GetEntryByUUID(entryUUID string) (*Card, error) {
	if v.db == nil {
		return nil, errors.New("vault is not initialized")
	}

	row := v.db.QueryRow(`
		SELECT uuid, type, created_at, field_updated_at, title,
		       subtitle, note, trashed, item.deleted, category,
		       label, value, key, last_used, sensitive, item.icon
		FROM item
		INNER JOIN itemfield ON uuid = item_uuid
		WHERE uuid = ? AND sensitive = 1
		LIMIT 1
	`, entryUUID)

	var card Card
	err := row.Scan(
		&card.UUID, &card.Type, &card.CreatedAt, &card.UpdatedAt, &card.Title,
		&card.Subtitle, &card.Note, &card.Trashed, &card.Deleted, &card.Category,
		&card.Label, &card.value, &card.itemKey, &card.LastUsed, &card.Sensitive, &card.Icon,
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not retrieve entry")
	}

	card.RawValue = card.value
	return &card, nil
}
