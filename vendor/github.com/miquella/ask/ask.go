package ask

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	isInteractive bool
	input         *os.File
	output        *os.File
)

func init() {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		isInteractive = true
		input = tty
		output = tty
	} else {
		input = os.Stdin
		output = os.Stdout
	}
}

func Close() error {
	inerr := CloseInput()
	outerr := CloseOutput()
	if inerr != nil {
		return inerr
	}
	return outerr
}

func CloseInput() error {
	return input.Close()
}

func CloseOutput() error {
	return output.Close()
}

func IsInteractive() bool {
	return isInteractive
}

func HiddenAsk(prompt string) (string, error) {
	err := stty("-echo")
	if err != nil {
		return "", err
	}
	defer stty("echo")

	err = Print(prompt)
	if err != nil {
		return "", err
	}

	defer Print("\n")
	return readline()
}

func Ask(prompt string) (string, error) {
	err := Print(prompt)
	if err != nil {
		return "", err
	}

	return readline()
}

func Print(str string) error {
	_, err := fmt.Fprint(output, str)
	return err
}

func readline() (string, error) {
	var err error
	var buffer bytes.Buffer
	var b [1]byte
	for {
		var n int
		n, err = input.Read(b[:])
		if b[0] == '\n' {
			break
		}
		if n > 0 {
			buffer.WriteByte(b[0])
		}
		if n == 0 || err != nil {
			break
		}
	}

	if err != nil && err != io.EOF {
		return "", err
	}
	return string(buffer.Bytes()), err
}

func stty(args ...string) error {
	// don't do anything if we're non-interactive
	if !isInteractive {
		return nil
	}

	cmd := exec.Command("stty", args...)
	// if stty wasn't found in path, try hard-coding it
	if filepath.Base(cmd.Path) == cmd.Path {
		cmd.Path = "/bin/stty"
	}

	cmd.Stdin = input
	cmd.Stdout = output

	return cmd.Run()
}
