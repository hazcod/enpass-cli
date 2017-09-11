# enpass-cli
Linux and Mac OS X Enpass commandline client

Based on [encpass-decryptor by steffen9000](https://github.com/steffen9000/enpass-decryptor)

-- Installation

Required system packages: `sqlcipher-dev` `python3`  `git`

Get the code:             `git clone https://github.com/heywoodlh/enpass-cli pass && cd pass/`

Required python packages: `python -m pip install -r requirements.txt`

Add this to your .bashrc: `eval "$(register-python-argcomplete pass)"`

Symlink to 'pass':	  `sudo ln -s /usr/bin/pass pass/pass.py && sudo chown $USER /usr/bin/pass && chown 555 /usr/bin/pass`


-- Usage

`pass --help`

If enpass has already been initialized and using the default ~/Documents/Enpass/walletx.db use this syntax:

`pass get github`

`pass copy github`

Specify another walletx file using the -w argument:

`pass -w=/Users/user/alternate-dir/walletx.db get github`

`pass -w=/Users/user/alternate-dir/walletx.db copy github`


 Delete password stored in keyring for OS X users:
 python3 -c "import keyring; keyring.delete_password('enpass', 'enpass')"
