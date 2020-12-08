enpass-cli
==========

A commandline utility for the Enpass password manager.

CLI Usage
-----
```shell
$ # set an alias to easily reuse
$ alias enp="enpasscli -vault=/my-vault-dir/ -type=password"

$ # show passwords of 'enpass.com'
$ enp show enpass.com

$ # copy password of 'reddit.com' entry to clipboard
$ enp copy reddit.com

$ # or list anything containing 'twitter' (without password)
$ enp list twitter
```

Testing Code
-------
```shell
$ go test -v $(go list ./... | grep -v /vendor/)
```

Using the library
-----------------
See the documentation on [pkg.go.dev](https://pkg.go.dev/github.com/hazcod/enpass-cli/pkg/enpass).
