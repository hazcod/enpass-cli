package clipboard

import (
	"github.com/atotto/clipboard"
)

func writeAll(text string) error {
	clipboard.Primary = Primary
	return clipboard.WriteAll(text)
}
