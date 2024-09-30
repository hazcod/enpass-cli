package clipboard

import (
	"fmt"
	"os"
	"os/exec"
)

// writes usinng the xclip command, might also
// work on freebsd and netbsd
func writeAll(text string) error {
	path, err := exec.LookPath("xclip")
	if err != nil {
		return fmt.Errorf("failed to find xclip: %w", err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create xclip pipe: %w", err)
	}
	var perr error
	go func() {
		_, err := w.WriteString(text)
		if err != nil {
			perr = fmt.Errorf("failed to write to xclip: %w", err)
		}
		w.Close() // ignore err
	}()

	c := exec.Cmd{
		Path: path,
		Args: []string{
			"-i",
			"-selection",
			"clipboard",
		},
		Stdin:  r,
		Stdout: nil,
		Stderr: nil,
	}
	err = c.Run()
	if err != nil {
		return fmt.Errorf("failed to run xclip: %w", err)
	}
	if perr != nil {
		return fmt.Errorf("failed to write to xclip: %w", err)
	}

	return nil
}
