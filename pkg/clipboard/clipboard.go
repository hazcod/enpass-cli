package clipboard

var (
	// using X selection primary if set to true and os allows for it
	Primary bool
)

// write : writes to the clipboard
func WriteAll(text string) (error) {
	return writeAll(text)
}
