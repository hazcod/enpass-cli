package enpass

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// EntryData holds the data for creating or updating an entry.
//
// Only login-shaped entries are supported: the writer populates the stock
// login.default template. Empty fields mean "leave unchanged" on update.
type EntryData struct {
	Title    string
	Username string
	Password string
	URL      string
	Notes    string
	Category string
}

// sqlExecutor is the subset of *sql.DB and *sql.Tx used by the schema helpers.
type sqlExecutor interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	Exec(query string, args ...interface{}) (sql.Result, error)
}

// tableColumns returns the set of columns that exist in table.
//
// Column sets differ between vaults: a vault created by Enpass 6.8 has fewer
// itemfield columns than one written by 6.12 (e.g. non_compliant and
// non_compliant_check_time). The writer therefore fills in only the columns the
// vault in front of it actually has, instead of failing on a version mismatch.
//
// table is always a compile-time constant from this package, so interpolating
// it into the query is safe; values are still passed as bound parameters.
//
// Example: tableColumns(tx, "item") == map[string]bool{"uuid": true, ...}
func tableColumns(q sqlExecutor, table string) (map[string]bool, error) {
	rows, err := q.Query("SELECT name FROM pragma_table_info('" + table + "')")
	if err != nil {
		return nil, errors.Wrapf(err, "could not read schema of %s", table)
	}
	defer rows.Close()

	columns := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, errors.Wrapf(err, "could not read column of %s", table)
		}
		columns[name] = true
	}

	return columns, rows.Err()
}

// insertRow inserts values into table, silently skipping keys the table does
// not have.
//
// Values must be a map of column name to value; unknown columns are dropped so
// one code path works against every vault schema version. Column order is
// sorted to keep the generated statement deterministic.
//
// Example: insertRow(tx, "itemfield", fieldCols, map[string]interface{}{"type": "username"})
func insertRow(q sqlExecutor, table string, available map[string]bool, values map[string]interface{}) error {
	names := sortedColumns(values, available)
	if len(names) == 0 {
		return errors.Errorf("no known columns to insert into %s", table)
	}

	placeholders := make([]string, len(names))
	args := make([]interface{}, len(names))
	for i, name := range names {
		placeholders[i] = "?"
		args[i] = values[name]
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		table, strings.Join(names, ", "), strings.Join(placeholders, ", "))

	_, err := q.Exec(query, args...)

	return err
}

// updateRow updates values in table where where, skipping unknown columns.
//
// Example: updateRow(tx, "item", itemCols, map[string]interface{}{"title": "new"}, "uuid = ?", id)
func updateRow(q sqlExecutor, table string, available map[string]bool, values map[string]interface{}, where string, whereArgs ...interface{}) (int64, error) {
	names := sortedColumns(values, available)
	if len(names) == 0 {
		return 0, nil
	}

	assignments := make([]string, len(names))
	args := make([]interface{}, 0, len(names)+len(whereArgs))
	for i, name := range names {
		assignments[i] = name + " = ?"
		args = append(args, values[name])
	}
	args = append(args, whereArgs...)

	query := fmt.Sprintf("UPDATE %s SET %s WHERE %s", table, strings.Join(assignments, ", "), where)
	result, err := q.Exec(query, args...)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// sortedColumns returns the keys of values that exist in available, sorted.
func sortedColumns(values map[string]interface{}, available map[string]bool) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		if available[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	return names
}

// CreateEntry creates a new login entry in the vault.
//
// The row is written in the shape the desktop app expects: a non-NULL
// item.template, a lower-case category, a JSON icon, the full stock
// login.default field set with Enpass's own item_field_uid/orde values, and the
// per-field hashes the app uses for its password-strength and duplicate
// detection. Writing a partial row is what made Enpass 6.12 crash with a NULL
// dereference while rendering, and left earlier versions showing unlabelled
// values.
//
// Only the login category is supported, because EntryData only carries login
// fields; passing any other category returns an error instead of writing a row
// the app cannot map onto a template.
//
// v.syncVaultInfo is called after the row is committed so vault.json keeps its
// item count and modification time in step with the database.
//
// Example: id, err := vault.CreateEntry(&EntryData{Title: "GitHub", Username: "me", Password: "s3cret"})
func (v *Vault) CreateEntry(entry *EntryData) (string, error) {
	if v.db == nil {
		return "", errors.New("vault is not initialized")
	}

	if entry.Title == "" {
		return "", errors.New("title is required")
	}

	category := strings.ToLower(strings.TrimSpace(entry.Category))
	if category == "" {
		category = loginCategory
	}
	if category != loginCategory {
		return "", errors.Errorf("unsupported category %q: only %q entries can be created", entry.Category, loginCategory)
	}

	entryUUID := uuid.New().String()
	now := time.Now().Unix()

	// One key per item, shared by every sensitive field.
	itemKey, err := NewItemKey()
	if err != nil {
		return "", err
	}

	encryptedPassword := ""
	if entry.Password != "" {
		encryptedPassword, err = EncryptValueWithKey(entry.Password, entryUUID, itemKey)
		if err != nil {
			return "", errors.Wrap(err, "could not encrypt password")
		}
	}

	tx, err := v.db.Begin()
	if err != nil {
		return "", errors.Wrap(err, "could not begin transaction")
	}
	defer tx.Rollback()

	itemColumns, err := tableColumns(tx, "item")
	if err != nil {
		return "", err
	}
	fieldColumns, err := tableColumns(tx, "itemfield")
	if err != nil {
		return "", err
	}

	err = insertRow(tx, "item", itemColumns, map[string]interface{}{
		"uuid":             entryUUID,
		"created_at":       now,
		"meta_updated_at":  now,
		"field_updated_at": now,
		"updated_at":       now,
		"title":            entry.Title,
		"subtitle":         entry.Username,
		"note":             entry.Notes,
		"icon":             loginIcon(entry.URL),
		"category":         category,
		"template":         loginTemplate,
		"auto_submit":      1,
		"favorite":         0,
		"trashed":          0,
		"archived":         0,
		"deleted":          0,
		"wearable":         0,
		"usage_count":      0,
		"last_used":        0,
		"form_data":        "",
		"extra":            "",
		"key":              itemKey,
	})
	if err != nil {
		return "", errors.Wrap(err, "could not insert item")
	}

	// Write the complete template, including the empty slots: the app maps
	// values onto template slots by uid, so a missing section or a missing
	// empty field shows up as an unlabelled, ungrouped entry.
	for _, field := range loginFields {
		storedValue, plainValue := "", ""
		switch field.fieldType {
		case "username":
			storedValue, plainValue = entry.Username, entry.Username
		case "password":
			storedValue, plainValue = encryptedPassword, entry.Password
		case "url":
			storedValue, plainValue = entry.URL, entry.URL
		}

		if err := insertTemplateField(tx, fieldColumns, entryUUID, field, storedValue, plainValue, now); err != nil {
			return "", errors.Wrapf(err, "could not insert %s field", field.fieldType)
		}
	}

	if err := tx.Commit(); err != nil {
		return "", errors.Wrap(err, "could not commit transaction")
	}

	v.syncVaultInfo()

	v.logger.WithField("uuid", entryUUID).Debug("created entry")

	return entryUUID, nil
}

// UpdateEntry updates an existing entry.
//
// Empty fields in updates are left untouched, matching the CLI's flag
// semantics. Sensitive updates reuse the item's existing key: Enpass encrypts
// every sensitive field of an item with that one key, so replacing it would
// leave the other sensitive fields (extra password slots, TOTP seeds) encrypted
// under a key the app no longer has.
//
// The password field is located by its template uid first and by type second,
// so entries written by older versions of this tool are repaired in place
// instead of gaining a duplicate field. A missing field is added using the
// stock template slot.
//
// Example: err := vault.UpdateEntry(id, &EntryData{Password: "new-secret"})
func (v *Vault) UpdateEntry(entryUUID string, updates *EntryData) error {
	if v.db == nil {
		return errors.New("vault is not initialized")
	}

	now := time.Now().Unix()

	tx, err := v.db.Begin()
	if err != nil {
		return errors.Wrap(err, "could not begin transaction")
	}
	defer tx.Rollback()

	var itemKey []byte
	var currentCategory, currentTemplate sql.NullString
	err = tx.QueryRow("SELECT key, category, template FROM item WHERE uuid = ?", entryUUID).
		Scan(&itemKey, &currentCategory, &currentTemplate)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("entry not found")
	} else if err != nil {
		return errors.Wrap(err, "could not read entry")
	}

	itemColumns, err := tableColumns(tx, "item")
	if err != nil {
		return err
	}
	fieldColumns, err := tableColumns(tx, "itemfield")
	if err != nil {
		return err
	}

	itemValues := map[string]interface{}{
		"field_updated_at": now,
		"meta_updated_at":  now,
		"updated_at":       now,
	}

	if updates.Title != "" {
		itemValues["title"] = updates.Title
	}
	if updates.Notes != "" {
		itemValues["note"] = updates.Notes
	}
	if updates.Category != "" {
		category := strings.ToLower(strings.TrimSpace(updates.Category))
		itemValues["category"] = category
		// Repair rows written before the template was set, so a later edit in
		// the app can resolve their labels.
		if category == loginCategory && currentTemplate.String == "" {
			itemValues["template"] = loginTemplate
		}
	}

	if updates.Username != "" {
		itemValues["subtitle"] = updates.Username
	}

	if updates.Password != "" {
		// Keep the existing key when there is one; only allocate a key for
		// items that never had a password (or were written without one).
		if len(itemKey) != 44 {
			itemKey, err = NewItemKey()
			if err != nil {
				return err
			}
			itemValues["key"] = itemKey
		}

		passwordField, ok := loginFieldByType("password")
		if !ok {
			return errors.New("login template has no password field")
		}

		encryptedPassword, err := EncryptValueWithKey(updates.Password, entryUUID, itemKey)
		if err != nil {
			return errors.Wrap(err, "could not encrypt password")
		}

		if err := applyField(tx, fieldColumns, entryUUID, passwordField, encryptedPassword, updates.Password, now); err != nil {
			return errors.Wrap(err, "could not update password field")
		}
	}

	if updates.Username != "" {
		usernameField, _ := loginFieldByType("username")
		if err := applyField(tx, fieldColumns, entryUUID, usernameField, updates.Username, updates.Username, now); err != nil {
			return errors.Wrap(err, "could not update username field")
		}
	}

	if updates.URL != "" {
		urlField, _ := loginFieldByType("url")
		if err := applyField(tx, fieldColumns, entryUUID, urlField, updates.URL, updates.URL, now); err != nil {
			return errors.Wrap(err, "could not update URL field")
		}
	}

	if _, err := updateRow(tx, "item", itemColumns, itemValues, "uuid = ?", entryUUID); err != nil {
		return errors.Wrap(err, "could not update item")
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "could not commit transaction")
	}

	v.syncVaultInfo()

	v.logger.WithField("uuid", entryUUID).Debug("updated entry")

	return nil
}

// applyField updates the field matching field's type, or inserts the template
// slot when the entry does not have it yet.
func applyField(q sqlExecutor, fieldColumns map[string]bool, itemUUID string, field templateField, storedValue, plainValue string, now int64) error {
	existing, found, err := findField(q, itemUUID, field)
	if err != nil {
		return err
	}

	if !found {
		return insertTemplateField(q, fieldColumns, itemUUID, field, storedValue, plainValue, now)
	}

	return updateField(q, fieldColumns, existing, field, storedValue, plainValue, now)
}

// fieldRow is the identifying part of an existing itemfield row.
type fieldRow struct {
	id  int64
	uid int
}

// findField locates the field row that should hold field, preferring the
// template uid and falling back to the first field of that type.
//
// The fallback is what lets an entry written by an older version of this tool
// (arbitrary uids, no orde) be updated instead of duplicated: the app treats a
// second password field as an extra slot, not as the same value.
//
// Example: findField(tx, id, passwordField) == {id: 42, uid: 11}, true, nil
func findField(q sqlExecutor, itemUUID string, field templateField) (fieldRow, bool, error) {
	var row fieldRow
	err := q.QueryRow(`
		SELECT ID, item_field_uid FROM itemfield
		WHERE item_uuid = ? AND type = ? AND deleted = 0
		ORDER BY (item_field_uid = ?) DESC, orde
		LIMIT 1
	`, itemUUID, field.fieldType, field.uid).Scan(&row.id, &row.uid)

	if errors.Is(err, sql.ErrNoRows) {
		return fieldRow{}, false, nil
	} else if err != nil {
		return fieldRow{}, false, errors.Wrap(err, "could not find field")
	}

	return row, true, nil
}

// insertTemplateField writes one field of the login template.
//
// storedValue is what goes into itemfield.value (ciphertext for sensitive
// fields), plainValue is the readable value used to compute hash and the
// password initials. The app expects a hash for every non-empty field, starts
// password strength at 0 and every other field at -1, and marks template slots
// as historical with algo_version 1.
func insertTemplateField(q sqlExecutor, fieldColumns map[string]bool, itemUUID string, field templateField, storedValue, plainValue string, now int64) error {
	initial := ""
	strength := -1
	if field.fieldType == "password" {
		initial = valueInitial(plainValue)
		strength = 0
	}

	return insertRow(q, "itemfield", fieldColumns, map[string]interface{}{
		"item_uuid":                itemUUID,
		"item_field_uid":           field.uid,
		"label":                    "",
		"value":                    storedValue,
		"deleted":                  0,
		"sensitive":                boolToInt(field.sensitive),
		"historical":               1,
		"type":                     field.fieldType,
		"form_id":                  "",
		"updated_at":               now,
		"value_updated_at":         now,
		"orde":                     field.orde,
		"wearable":                 0,
		"history":                  "",
		"initial":                  initial,
		"hash":                     valueHash(plainValue),
		"strength":                 strength,
		"algo_version":             1,
		"expiry":                   0,
		"excluded":                 0,
		"pwned_check_time":         now,
		"extra":                    "",
		"non_compliant":            0,
		"non_compliant_check_time": 0,
	})
}

// updateField rewrites one existing field in place, keeping its uid and order.
func updateField(q sqlExecutor, fieldColumns map[string]bool, existing fieldRow, field templateField, storedValue, plainValue string, now int64) error {
	values := map[string]interface{}{
		"value":            storedValue,
		"hash":             valueHash(plainValue),
		"updated_at":       now,
		"value_updated_at": now,
	}

	// The app only shows initials and a strength score for passwords.
	if field.fieldType == "password" {
		values["initial"] = valueInitial(plainValue)
		values["strength"] = 0
	}

	_, err := updateRow(q, "itemfield", fieldColumns, values, "ID = ?", existing.id)

	return err
}

// boolToInt converts a bool into the 0/1 SQLite uses for its boolean columns.
func boolToInt(value bool) int {
	if value {
		return 1
	}

	return 0
}

// TrashEntry moves an entry to the trash
func (v *Vault) TrashEntry(entryUUID string) error {
	if v.db == nil {
		return errors.New("vault is not initialized")
	}

	now := time.Now().Unix()
	result, err := v.db.Exec("UPDATE item SET trashed = 1, field_updated_at = ?, meta_updated_at = ?, updated_at = ? WHERE uuid = ?",
		now, now, now, entryUUID)
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
	result, err := v.db.Exec("UPDATE item SET trashed = 0, field_updated_at = ?, meta_updated_at = ?, updated_at = ? WHERE uuid = ?",
		now, now, now, entryUUID)
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

	v.syncVaultInfo()

	v.logger.WithField("uuid", entryUUID).Debug("deleted entry")
	return nil
}

// GetEntryByUUID retrieves a single entry by its UUID (including trashed)
func (v *Vault) GetEntryByUUID(entryUUID string) (*Card, error) {
	if v.db == nil {
		return nil, errors.New("vault is not initialized")
	}

	row := v.db.QueryRow(`
		SELECT item.uuid, itemfield.type, item.created_at, item.field_updated_at, item.title,
		       item.subtitle, item.note, item.trashed, item.deleted, item.category,
		       itemfield.label, itemfield.value, item.key, item.last_used, itemfield.sensitive, item.icon
		FROM item
		INNER JOIN itemfield ON item.uuid = itemfield.item_uuid
		WHERE item.uuid = ? AND itemfield.sensitive = 1
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
