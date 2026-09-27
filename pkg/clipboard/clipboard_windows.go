package clipboard

import (
	"github.com/atotto/clipboard"
)

func writeAll(text string) error {
	return clipboard.WriteAll(text)
}
