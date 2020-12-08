ask
===

A Golang library for prompting a user for passwords and such.

Reading from `stdin` and writing to `stdout` interferes with a user's ability
to pipe data into or out of a program. This is most evident when doing things
such as prompting a user for a password.

For example, given a program which requests a password from a user and then
proceeds to read the remainder of `stdin` as input. If the user then pipes a
file into the program, the first line is read as the password rather than the
user being given an opportunity to enter the correct password.

Instead, this library interacts with the user directly, allowing the user to be
prompted and respond without interfering with `stdin` or `stdout`.

*__Use judiciously.__ While it may be tempting to use this as the only input
method for a program, this precludes a user from automating input.*

Usage
-----

`ask.Ask` gets input from the user normally, while `ask.HiddenAsk` prevents
echoing of the user's input. `ask.Print` is also available to compliment
the `ask.Ask*` variants.

```golang
import (
  "github.com/miquella/ask"
)

func getPassword() (string, error) {
    err := ask.Print("Warning! I am about to ask you for a password!\n")
    if err != nil {
        return "", err
    }

    return ask.HiddenAsk("Password: ")
}
```
