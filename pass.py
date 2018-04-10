#!/usr/bin/env /usr/local/bin/python3
# -*- coding: utf-8 -*-

# PYTHON_ARGCOMPLETE_OK
from Crypto.Cipher import AES
import hashlib, binascii

import json
import getpass
import time
import subprocess
import os
import argparse, argcomplete
import sys
import keyring
from pysqlcipher3 import dbapi2 as sqlite

# To get all types of information decrypted run this:
# print(pad(field['label']) +  ": " + field['type'])

# Set up wallet variable. Change wallet variable to other location if needed
wallet = os.getenv('HOME') + '/Documents/Enpass/walletx.db'
password_store_decline = os.getenv('HOME') + '/Documents/Enpass/.store_decline'

def pad(msg):
    return " "*2 + msg.ljust(12)

def getScriptPath():
    return os.path.dirname(os.path.realpath(sys.argv[0]))

def abort(message):
    warn("Abort: " + message)
    sys.exit(1)

def warn(message):
    print(message, file=sys.stderr)

class Chooser:
    import os, sys

    def __init__(self, choices):
        self.choices = choices

    def appleScriptChooser(self):
        import tempfile
        """
        give user a choice of items. return selected item
        """
        self.SLABSCRIPT = """
                tell app "System Events"
                        Activate

                        set AccountList to {}
                        set Answer to (choose from list AccountList with title "Select Account")

                        if Answer is false then
                                error number -128 (* user cancelled *)
                        else
                                set Answer to Answer's item 1 (* extract choice from list *)
                        end if
                end tell
                tell app "iTerm2"
                        Activate
                        return Answer
                end tell
        """
        fd = tempfile.NamedTemporaryFile(delete=False)
        # Oh, AD, you special, special child...
        s = '{ "' + '", "'.join(sorted(self.choices)).replace('\\', '\\\\') + '" }'
        fd.write(self.SLABSCRIPT.format(s).encode('utf-8'))
        name = fd.name
        fd.close()

        try:
            out = subprocess.check_output(['/usr/bin/osascript', name], universal_newlines=True)
            out = out.rstrip()
        except:
            sys.exit()

        os.unlink(name)
        return out

    def chooseGUIChooser(self):
        """
        use choose gui for choices
        https://github.com/sdegutis/choose
        """
        try:
            out = subprocess.run(['/usr/local/bin/choose'], stdout=subprocess.PIPE, input='\n'.join(sorted(self.choices)), universal_newlines=True)
        except:
            sys.exit()
        return out.stdout.strip()

    def zenityGUIChooser(self):
        """
        use zenity gui for choices
        """
        try:
            out = subprocess.run(['/usr/bin/zenity', '--list', '--text', 'Please select the account', '--column', 'Accounts'], stdout=subprocess.PIPE, input='\n'.join(sorted(self.choices)), universal_newlines=True)
        except:
            sys.exit()
        return out.stdout.strip()

    def dumbCLIChooser(self):
        """
        use the dumb chooser... Rather this than figting with dialog!
        """
        def __pad(msg, length=12):
            return " "*2 + msg.ljust(length)

        cards = []
        print()

        for card in sorted(self.choices):
            cards.append(card)
            print(__pad(str(len(cards)) + '. ', 4) + card)

        try:
            print()
            selection = input('Select account (1-' + str(len(cards)) + '): ')
            selection = int(selection)-1
        except ValueError:
            print('Invalid selection')
            sys.exit(1)

        return cards[selection]
            
    def choice(self):
        """
        give user a choice of items, return selected item
        if choose-gui is installed, use that, otherwise fall back to applescript
        """
        if os.path.exists('/usr/local/bin/choose'):
            return self.chooseGUIChooser()
        elif sys.platform == 'darwin':
            return self.appleScriptChooser()
        elif os.path.exists('/usr/bin/zenity'):
            return self.zenityGUIChooser()
        else:
            return self.dumbCLIChooser()


class Enpassant:
    def __init__(self, filename, password):
        self.initDb(filename, password)
        self.crypto = self.getCryptoParams()

    def __getScriptPath(self):
        import os
        return os.path.dirname(os.path.realpath(sys.argv[0]))

    # Sets up SQLite DB
    def initDb(self, filename, password):
        self.conn = sqlite.connect(filename)
        self.c = self.conn.cursor()
        self.c.row_factory = sqlite.Row
        self.c.execute("PRAGMA key='" + password + "'")
        self.c.execute("PRAGMA kdf_iter = 24000")

    def generateKey(self, key, salt):
        # 2 Iterations of PBKDF2 SHA256
        return hashlib.pbkdf2_hmac('sha256', key, salt, 2)

    def getCryptoParams(self):
        ret = {}
        # Identity contains stuff to decrypt data columns
        try:
            self.c.execute("SELECT * FROM Identity")
        except sqlite.DatabaseError:
            print("Invalid password")
            sys.exit(1)

        identity = self.c.fetchone()

        # Info contains more parameters
        info = identity["Info"]

        # Get params from stream
        i = 16 # First 16 bytes are for "mHashData", which is unused
        ret["iv"] = bytearray()
        salt = bytearray()
        while i <= 31:
            ret["iv"].append(info[i])
            i += 1
        while i <= 47:
            salt.append(info[i])
            i += 1

        ret["iv"]  = bytes(ret["iv"])
        ret["key"] = self.generateKey(identity["Hash"].encode('utf-8'), salt)

        return ret

    def unpad(self, s):
        return s[0:-ord(s[-1])]

    def decrypt(self, enc, key, iv):
        # PKCS5
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return self.unpad(str(cipher.decrypt(enc), 'utf-8'))

    def getCards(self, name):
        results = []
        name = name.lower()
        self.c.execute("SELECT * FROM Cards")
        cards = self.c.fetchall()
        with open(self.__getScriptPath() + '/.enpass', encoding='utf8', mode='w') as f:
            # File used for Bash/Zsh Command Completion...

            for card in cards:
                dec = self.decrypt(card["Data"], self.crypto["key"], self.crypto["iv"])
                card = json.loads(dec)

                if name == 'sudolikeaboss':
                    for field in sorted(card["fields"], key=lambda x:x['label']):
                        if field['type'] == 'url' and field['label'].lower() == 'location' and 'sudolikeaboss' in field['value']:
                            results.append(card)
                elif name == '*' and len(card["fields"]) > 0:
                    results.append(card)
                elif name in card["name"].lower() and len(card["fields"]) > 0:
                    results.append(card)

                f.write(card['name'].lower() + "\n")

        return results


def CardCompleter(prefix, **kwargs):
    # Bask/Zsh Command Completion...
    prefix = prefix.lower()
    return list(line for line in open(getScriptPath() + '/.enpass','r').read().splitlines() if line.startswith(prefix))


class PassCards:
    import sys

    def __init__(self, cardlist):
        self.carddata = {}

        for card in cardlist:

            self.carddata[card['uuid']] = {}
            self.carddata[card['uuid']]['name'] = card['name']

            # self.__warn("\n" + card['name'])

            for field in sorted(card["fields"], key=lambda x:x['label']):
            # for field in card["fields"]:

                if field['isdeleted'] == 1:         # Skip if deleted...
                    continue

                if field['type'] == 'username' and field['value'] != '' \
                    and not 'username' in self.carddata[card['uuid']]:
                    self.carddata[card['uuid']]['username'] = field['value']

                elif field['type'] == 'email' and field['value'] != '' \
                    and not 'email' in self.carddata[card['uuid']]:
                    self.carddata[card['uuid']]['email']    = field['value']

                elif field['type'] == 'url' and field['value'] != '' \
                    and field['label'].lower() == 'website' and not 'website' in self.carddata[card['uuid']]:
                    self.carddata[card['uuid']]['website']  = field['value']

                elif field['type'] == 'url' and field['value'] != '' \
                    and field['label'].lower() == 'location' and not 'location' in self.carddata[card['uuid']]:
                     self.carddata[card['uuid']]['location'] = field['value']

                elif field['type'] == 'password' and field['isdeleted'] != 1 and field['value'] != '' \
                    and field['label'].lower() != 'passwordhistory' \
                    and not 'password' in self.carddata[card['uuid']]:
                    self.carddata[card['uuid']]['password'] = field['value']

                elif field['value'] != '':
                    if not 'additional' in self.carddata[card['uuid']]:
                        self.carddata[card['uuid']]['additional'] = []
                    self.carddata[card['uuid']]['additional'].append([field['label'], field['type'], field['value']])

            if card['note'] != '':
                self.carddata[card['uuid']]['note'] = card['note']

    def __pad(self, msg, length=12):
        return " "*2 + msg.ljust(length)

    def __warn(self, message):
        print(message, file=sys.stderr)

    def __quit(self, message):
        import sys
        print(message, file=sys.stderr)
        sys.exit(1)

    def copyToClip(self, message):
        if sys.platform == 'darwin':
            p = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE, close_fds=True)
            p.communicate(input=message.encode('utf-8'))
        elif sys.platform == 'linux':
            p = subprocess.Popen(['xclip', '-in', '-selection', 'clipboard'], stdin=subprocess.PIPE, close_fds=True)
            p.communicate(input=message.encode('utf-8'))
        else:
            self.__quit("No pasteboard integration for '" + sys.platform + "'; please consider using the 'print' command")

    def __getTermSize(self):
        """
        returns (lines:int, cols:int)
        """
        import os, struct
        def ioctl_GWINSZ(fd):
            import fcntl, termios
            return struct.unpack("hh", fcntl.ioctl(fd, termios.TIOCGWINSZ, "1234"))

        # try stdin, stdout, stderr
        for fd in (0, 1, 2):
            try:
                return ioctl_GWINSZ(fd)
            except:
                pass

        # try os.ctermid()
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            try:
                return ioctl_GWINSZ(fd)
            finally:
                os.close(fd)
        except:
            pass

        # try `stty size`
        try:
            return tuple(int(x) for x in os.popen("stty size", "r").read().split())
        except:
            pass

        # try environment variables
        try:
            return tuple(int(os.getenv(var)) for var in ("LINES", "COLUMNS"))
        except:
            pass

        # i give up. return default.
        return (25, 80)

    def displayCards(self, alldata="no", passwords="no"):
        import textwrap
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent = pad('') + "  "
        wrapper.subsequent_indent = pad('') + "  "
        wrapper.width = self.__getTermSize()[1]

        for uuid in sorted(self.carddata.keys()):
            print(self.carddata[uuid]['name'])
            print(len(self.carddata[uuid]['name'])*'-')
            if 'username' in self.carddata[uuid]: print(self.__pad("User Name") + ': ' + self.carddata[uuid]['username'])
            if 'email' in self.carddata[uuid]:    print(self.__pad("Email")     + ': ' + self.carddata[uuid]['email'])
            if 'website' in self.carddata[uuid]:  print(self.__pad("Website")   + ': ' + self.carddata[uuid]['website'])
            if 'location' in self.carddata[uuid]: print(self.__pad("Location ") + ': ' + self.carddata[uuid]['location'])

            if 'password' in self.carddata[uuid]:
                 print(self.__pad("Password")  + ': ', end='')
                 if passwords == "no":
                     print("Defined")
                 else:
                     print(self.carddata[uuid]['password'])

            if 'note' in self.carddata[uuid]:
                print(self.__pad("Note") + ': ' + wrapper.fill(self.carddata[uuid]['note']).strip())

            if alldata != 'no':
                if 'additional' in self.carddata[uuid]:
                    print("\n Additional Data\n")
                    for dset in (self.carddata[uuid]['additional']):
                        print(self.__pad(dset[0], 22) + ': ', end='')

                        if passwords == "no" and dset[1].lower() == 'password':
                            print("Defined")
                        else:
                            print(self.__pad(dset[2], 22) + "(" + dset[1] + ")")

            print()

    def selectCard(self):

        if len(self.carddata) > 1:
            choices = {}

            for uuid in sorted(self.carddata.keys()):
                if 'username' in self.carddata[uuid]:
                    choices[self.carddata[uuid]['name'] + " - " + self.carddata[uuid]['username']] = uuid
                else:
                    choices[self.carddata[uuid]['name']] = uuid

            chooser = Chooser(choices.keys())
            selection = chooser.choice()
            try:
                return choices[selection]
            except KeyError:
                self.__quit("No password defined for '" + selection + "'")

        else:
            return list(self.carddata)[0]

    def processCard(self, entry, command):

        if command == 'copy' or command == 'quietcopy':
            try:
                self.copyToClip(self.carddata[entry]['password'])
                if command == 'copy':
                    print("Copied password for '" + self.carddata[entry]['name'] + "' to the pasteboard")
            except KeyError:
                self.__quit("No password defined for '" + self.carddata[entry]['name'] + "'")

        else:
            print(self.carddata[entry]['password'])


def main(argv=None):
    import sys
    global wallet

    command = ''
    name    = ''

    alldata  = 'no'
    showpass = 'no'

    if argv is None:
        parser = argparse.ArgumentParser ()
        parser.add_argument('-q', '--quiet', action='store_true', help='Supress Standard Output Notifications')

        parser.add_argument('-w', '--wallet', help='The Enpass wallet file')

        parser.add_argument('-a', '--alldata', action='store_true', help='Displays all of the known data in of each card')
        parser.add_argument('--please_show_me_the_passwords', action='store_true', help='Display passwords where present')

        parser.add_argument("command", choices=('get', 'list', 'copy', 'print'), help="Show entry, copy or print password")
        parser.add_argument("name", help="The entry name, use '*' to see all").completer = CardCompleter

        argcomplete.autocomplete(parser)
        args = parser.parse_args()

        command = args.command
        name = args.name

        if args.wallet is not None:
            wallet = args.wallet
        if args.alldata is True:
            alldata = 'yes'
        if args.please_show_me_the_passwords is True:
            showpass = 'yes'
        if args.quiet is True and command == 'copy':
            command = 'quietcopy'
        if command == 'print' and showpass != 'yes':
            abort("Please verify the printing of the passwords using '--please_show_me_the_passwords'")

    else:
        if len(argv) != 3:
            abort("Args: command wallet name")

        command = argv[0]
        if not wallet:
            wallet = argv[1]

        name = argv[2]

    if (args.command is None or args.command not in ['copy','get','list','print','quietcopy']):
        abort("Command: get, list, copy, print")

    if not os.path.isfile(wallet):
        abort("Wallet not found: " + wallet)

    password = keyring.get_password('enpass', 'enpass')
    if password is None:
        password = getpass.getpass("Master Password: ")
        if os.path.isfile(password_store_decline):
            pass
        else:
            response = input('Would you like to save your master password in the keyring? (Y/n)').lower()
            if response == 'y' or response == '':
                keyring.set_password('enpass', 'enpass', str(password))
            else:
                open(password_store_decline, 'w')

    en = Enpassant(wallet, str(password))
    cards = en.getCards(name)

    if len(cards) == 0:
        abort("No entries for '" + name + "'")

    carddata = PassCards(cards)

    if command == "list" or command == "get":
        carddata.displayCards(alldata, showpass)
    else:
        carddata.processCard(carddata.selectCard(), command)

if __name__ == "__main__":
    exit(main())
