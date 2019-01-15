# enpass-cli

**WARNING:** This is currently not compatible with Enpass 6.0. I'm doing [some testing](https://github.com/HazCod/enpass-cli-test/), but no results yet.

A Enpass command line client for Linux and macOS based on [enpass-decryptor](https://github.com/steffen9000/enpass-decryptor) by steffen9000.

**Warning:** I no longer use Enpass personally, so this repo needs a new maintainer. I will however still merge PRs.

## Installation

1. Required system packages:

	 - `sqlcipher-dev`
	 - `python3`
	 - `git`

2. Get the code:

		$ git clone https://github.com/HazCod/enpass-cli pass && cd pass/

3. Required python packages:

		$ pip3 install -r requirements.txt

4. Symlink to 'pass':

		$ sudo cp pass.py /usr/local/bin/pass && sudo chown $USER /usr/local/bin/pass

5. For autocompletion, add this line to your `.bashrc` file:

		$ eval "$(register-python-argcomplete pass)"

## Usage

For the current command line help, please run `pass --help`.

The `pass` command currently accepts the following arguments and commands:

Arguments:

 - `-q`, `--quiet`\
 	supress Standard Output Notifications

 - `-w WALLET`, `--wallet WALLET`\
 	Define the Enpass wallet file

 - `-a`, `--alldata`\
 	Displays all of the known data in of each card (useful in cases where you want to look at *Software Licences*, for instance)

 - `--please_show_me_the_passwords`\
 	Display passwords where present

Commands:

 - `get` and `list` displays the cards on the command line (use '*' to list all),
 - `copy` copies the password into the pasteboard, and
 - `print` prints the password to STDOUT iff `--please_show_me_the_passwords` has been given.

Examples:

1. If enpass has already been initialized and using the default `~/Documents/Enpass/walletx.db` use this syntax:

		$ pass get github
		$ pass copy github

2. Specify another walletx file using the -w argument:

		$ pass -w /Users/user/alternate-dir/walletx.db get github
		$ pass -w /Users/user/alternate-dir/walletx.db copy github

3. Delete password stored in keyring:
 
		$ python3 -c "import keyring; keyring.delete_password('enpass', 'enpass')"

4. If you decline to store your password, an empty file is created in ~/Documents/Enpass/ called .store_decline. If you change your mind and would like to store the password, remove this file:

		$ rm ~/Documents/Enpass/.store_decline

5. Dsiplay all known items about an entry:

		$ pass list -a Chikoo
