# enpass-cli
Enpass commandline client

Based on [encpass-decryptor by steffen9000](https://github.com/steffen9000/enpass-decryptor)

-- Installation

Required system packages: `sqlcipher-dev` `python3` `xclip` `git`

Get the code:             `git clone https://github.com/HazCod/enpass-cli pass && cd pass/`

Required python packages: `python -m pip install -r requirements.txt`

Add this to your .bashrc: `eval "$(register-python-argcomplete pass)"`

Symlink to 'pass':	  `sudo ln -s /usr/bin/pass pass/pass.py && sudo chown $USER /usr/bin/pass && chown 555 /usr/bin/pass`


-- Usage

`pass --help`

`pass -w=/home/user/Enpass/walletx.db get github`

`pass -w=/home/user/Enpass/walletx.db copy github`
