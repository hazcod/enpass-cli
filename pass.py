#!/usr/bin/env python3
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

##To get all types of information decrypted run this:
#print( pad(field['label']) +  " : " + field['type'])

## Set up wallet variable. Change wallet variable to other location if needed
wallet = os.getenv('HOME') + '/Documents/Enpass/walletx.db'

password_store_decline = os.getenv('HOME') + '/Documents/Enpass/.store_decline'

if sys.platform == 'darwin':
    def copyToClip(message):
        p = subprocess.Popen(['pbcopy'],
                            stdin=subprocess.PIPE, close_fds=True)
        p.communicate(input=message.encode('utf-8'))

if sys.platform == 'linux':
    def copyToClip(message):
        p = subprocess.Popen(['xclip', '-in', '-selection', 'clipboard'],
                            stdin=subprocess.PIPE, close_fds=True)
        p.communicate(input=message.encode('utf-8'))

def pad(msg):
    return " "*2 + msg.ljust(18)

def getScriptPath():
    return os.path.dirname(os.path.realpath(sys.argv[0]))

class Enpassant:
    def __init__(self, filename, password):
        self.initDb(filename, password)
        self.crypto = self.getCryptoParams()


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
            ret["iv"].append( info[i] )
            i += 1
        while i <= 47:
            salt.append( info[i] )
            i += 1

        ret["iv"]  = bytes(ret["iv"])
        ret["key"] = self.generateKey(identity["Hash"].encode('utf-8'), salt)

        return ret

    def unpad(self, s):
        return s[0:-ord(s[-1])]


    def decrypt(self, enc, key, iv ):
        # PKCS5
        cipher = AES.new(key, AES.MODE_CBC, iv )
        return self.unpad(str(cipher.decrypt(enc), 'utf-8'))

    def getCards(self, name):
        results = []
        name = name.lower ()
        self.c.execute("SELECT * FROM Cards")
        cards = self.c.fetchall()
        with open( getScriptPath() + '/.enpass', 'w' ) as f:
            for card in cards:
                dec = self.decrypt(card["Data"], self.crypto["key"], self.crypto["iv"])
                card = json.loads(dec)
                if name in card["name"].lower() and len(card["fields"]) > 0:
                    results.append( card )

                f.write( card['name'].lower() + "\n" )
        return results


def CardCompleter(prefix, **kwargs):
    prefix = prefix.lower()
    return list(line for line in open( getScriptPath() + '/.enpass','r' ).read().splitlines() if line.startswith(prefix))



def main(argv=None):
    import sys
    global wallet

    command = ''
    name    = ''

    if argv is None:
        parser = argparse.ArgumentParser ()

        parser.add_argument('-w', '--wallet', help='The Enpass wallet file')
        parser.add_argument("command", choices=('get', 'copy'), help="Show entry, copy password")
        parser.add_argument("name", help="The entry name").completer = CardCompleter

        argcomplete.autocomplete( parser )
        args = parser.parse_args()

        command = args.command
        name = args.name
        if args.wallet is not None:
            wallet = args.wallet
    else:
        if len(argv) != 3:
            print("Args: command wallet name")
            sys.exit(1)

        command = argv[0]
        if not wallet:
            wallet  = argv[1]
        name    = argv[2]

    if (args.command is None or args.command not in ['copy','get']):
        print("Command: copy, get")
        sys.exit(1)

    if not os.path.isfile( wallet ):
        print("Wallet not found: " + wallet)
        sys.exit(1)

    password = keyring.get_password('enpass', 'enpass')
    if password is None:
        password = getpass.getpass( "Master Password: " )
        if os.path.isfile(password_store_decline):
            pass
        else:
            response = input('Would you like to save your master password in the keyring? (Y/n)').lower()
            if response == 'y' or response == '':
                keyring.set_password('enpass', 'enpass', str(password))
            else:
                open(password_store_decline, 'w')

    en = Enpassant(wallet, str(password))
    cards = en.getCards( name )

    if command == "copy":
        if len(cards) == 0:
            print( "No entries for " + name )
            sys.exit(1)
        elif len(cards) > 1:
            value = 0
            multi_cards = []
            pass_list = []
            for card in cards:
                value += 1
                print( str(value) + '. ' + card["name"] )
                cardName = card["name"] + str(value)
                multi_cards.append( value )
                for field in sorted( card["fields"], key=lambda x:x['label'] ):
                    #print( pad(field['label']) +  " : " + field['type'])
                    if field['type'] == 'username':
                        print( pad(field['label']) + " : " + field['value'])
                    elif field['type'] == 'email':
                        print( pad(field['label']) + " : " + field['value'] )
                    if field['type'] == 'password':
                        pass_list.append( field['value'] )

                print('')
            try:
                print('')
                print( name + ' accounts: ')
                print(multi_cards)
                print('')
                selection = input('Select account: ')
                copyToClip( pass_list[int(selection)] )
                sys.exit(0)
            except ValueError:
                print('Invalid selection')
                sys.exit(1)



    for card in cards:
        if (command == "get"):
            print( pad("Name") + " : " + card["name"] )

        for field in sorted( card["fields"], key=lambda x:x['label'] ):
            if (command == "get"):
                if field['type'] == 'username':
                    print( pad(field['label']) + " : " + field['value'])
                elif field['type'] == 'email':
                    print( pad(field['label']) + " : " + field['value'] )
                elif field['type'] == 'url':
                    print( pad(field['label']) + " : " + field['value'] )
                elif field['type'] == 'text':
                    print( pad(field['label']) + " : " + field['value'] )

            if command == 'copy':
                if field['type'] == 'password':
                    copyToClip( field['value'] )
                elif field['type'] == 'username':
                    print( 'Copied for user ' + field['value'] )

        if (command == 'get'):
            print( pad('Note') + " :\n" + card['note'] )

if __name__ == "__main__":
    exit( main() )
