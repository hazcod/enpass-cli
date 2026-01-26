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

$ # create a new entry
$ enp create -title="My Service" -login="user@example.com" -password="secret123" -url="https://example.com"

$ # edit an existing entry
$ enp edit github.com -password="newsecret"

$ # move an entry to trash
$ enp trash github.com

$ # restore an entry from trash
$ enp restore github.com

$ # permanently delete a trashed entry
$ enp delete github.com
```

Commands
-----
| Name | Description |
| :---: | --- |
| `list FILTER` | List vault entries matching FILTER without password |
| `show FILTER` | List vault entries matching FILTER with password |
| `copy FILTER` | Copy the password of a vault entry matching FILTER to the clipboard |
| `pass FILTER` | Print the password of a vault entry matching FILTER to stdout |
| `create` | Create a new entry in the vault |
| `edit FILTER` | Edit an existing entry matching FILTER |
| `trash FILTER` | Move an entry matching FILTER to the trash |
| `restore FILTER` | Restore an entry matching FILTER from the trash |
| `delete FILTER` | Permanently delete a trashed entry matching FILTER |
| `dryrun` | Opens the vault without reading anything from it |
| `version` | Print the version |
| `help` | Print the help text |

Flags
-----
| Name | Description |
| :---: | --- |
| `-vault=PATH` | Path to your Enpass vault |
| `-keyfile=PATH` | Path to your Enpass vault keyfile |
| `-type=TYPE` | The type of your card (password, ...) |
| `-log=LEVEL` | The log level from debug (5) to error (1) |
| `-nonInteractive` | Disable prompts and fail instead |
| `-json` | Output as JSON to stdout |
| `-pin` | Enable Quick Unlock using a PIN |
| `-and` | Combines filters with AND instead of default OR |
| `-sort` | Sort the output by title and username of the `list` and `show` command |
| `-trashed` | Show trashed items in the `list` and `show` command |
| `-clipboardPrimary` | Use primary X selection instead of clipboard for the `copy` command |
| `-title=TITLE` | Title for `create`/`edit` commands |
| `-login=LOGIN` | Login/username for `create`/`edit` commands |
| `-password=PASSWORD` | Password for `create`/`edit` commands |
| `-url=URL` | URL for `create`/`edit` commands |
| `-notes=NOTES` | Notes for `create`/`edit` commands |
| `-category=CATEGORY` | Category for `create`/`edit` commands (default: Login) |
| `-force` | Skip confirmation prompts for `trash`/`delete` commands |

Development
-----
```shell
# to run it from code
% go run ./cmd/... -vault=foo list

# to build it yourself
% make build
% ./enpass-cli -vault=foo list
```

Testing Code
-------
```shell
$ go test -v $(go list ./... | grep -v /vendor/)
```

Using the library
-----------------
See the documentation on [pkg.go.dev](https://pkg.go.dev/github.com/hazcod/enpass-cli/pkg/enpass).
