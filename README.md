enpass-cli
==========

A commandline utility for the Enpass password manager.

Installation
-----
Go get yourself a compiled binary from [the releases page](https://github.com/hazcod/enpass-cli/releases).

CLI Usage
-----
```shell
$ # set an alias to easily reuse
$ alias enp="enpasscli -vault=/my-vault-dir/ -sort"

$ # list anything containing 'twitter' (without password)
$ enp list twitter

$ # show passwords of 'enpass.com'
$ enp show enpass.com

$ # copy password of 'reddit.com' entry to clipboard
$ enp copy reddit.com

$ # print password of 'github.com' to stdout, useful for scripting 
$ password=$(enp pass github.com)
```

Commands
-----
| Name | Description |
| :---: | --- |
| `list FILTER` | List vault entries matching FILTER without password |
| `show FILTER` | List vault entries matching FILTER with password |
| `copy FILTER` | Copy the password of a vault entry matching FILTER to the clipboard |
| `pass FILTER` | Print the password of a vaulty entry matching FILTER to stdout |
| `version` | Print the version |

Flags
-----
| Name | Description |
| :---: | --- |
| `-vault` | Path to your Enpass vault |
| `-keyfile` | Path to your Enpass vault keyfile |
| `-type` | The type of your card. (password, ...) |
| `-log` | The log level from debug (5) to error (1) |
| `-nonInteractive` | Disable prompts and fail instead |
| `-sort` | Sort the output by title and username of the `list` and `show` command |
| `-trashed` | Show trashed items in the `list` and `show` command |
| `-clipboardPrimary` | Use primary X selection instead of clipboard for the `copy` command |

Testing Code
-------
```shell
$ go test -v $(go list ./... | grep -v /vendor/)
```

Using the library
-----------------
See the documentation on [pkg.go.dev](https://pkg.go.dev/github.com/hazcod/enpass-cli/pkg/enpass).
