'''
Local String Encryption Tool v1.0.4
'''

from ast import Continue
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import getpass
import pyperclip
from datetime import datetime
import base64

KEY = bytes
PASSWORD = bytes
SALT = bytes

# create master password (only executes if there is no 'main_secret.txt' file present in the folder)
def gen_main_secret():
    while True:
        password = getpass.getpass('Enter your desired master password: ')
        password2 = getpass.getpass('Re-enter your password: ')
        if password == password2:
            break
        else:
            print('**Passwords do not match. Try again...**\n')


    password = bytes(password.encode('utf-8'))
    PASSWORD = password
    # KEY = Fernet.generate_key()
    ### ###
    # replaced above random key generation with a static salted key gen so only a password is required (v1.0.2 -> v1.0.3)
    SALT = b'\xcdS:\x80\xdc\x8b)\x90IT\xd5\xbb\x93\x80\xc2\xd8'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    KEY = base64.urlsafe_b64encode(kdf.derive(password))
    ### ###

    with open('master_secret.txt', 'w') as f:
        f.write(Fernet(KEY).encrypt(password).decode())

    print('Success! \n**Encrypted password created in "master_secret.txt"**\n')
    # print('----\/Key for decrypting\/----')
    # print(KEY.decode())
    # print('----/\Key for decrypting/\----\n')
    # pyperclip.copy(KEY.decode())
    # print('**Key copied to clipboard successfully**\nKeep your key in a safe place and use for decrypting this program...')
    datetimestamp = datetime.now()
    with open('history.txt', 'a+') as f:
        f.write(f'{datetimestamp}: {os.getlogin()} generated master password\n')

# authenticate with master password and user password input
def authenticate():
    password = getpass.getpass('Enter your password: ')

    password = bytes(password.encode('utf-8'))

    PASSWORD = password

    with open('master_secret.txt', 'r') as f:
        encrypted_password = bytes(f.read().encode('utf-8'))

    # key = bytes(getpass.getpass('Paste your key: ').encode('utf-8'))
    ### ###
    # replaced above key requirement with static salt generated key so only a password is required (v1.0.2 -> v1.0.3)
    SALT = b'\xcdS:\x80\xdc\x8b)\x90IT\xd5\xbb\x93\x80\xc2\xd8'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    ### ###

    KEY = key

    if password.decode() == Fernet(key).decrypt(encrypted_password).decode():
        datetimestamp = datetime.now()
        with open('history.txt', 'a+') as f:
            f.write(f'{datetimestamp}: {os.getlogin()} successfully logged in\n')
        return "success", key
    else:
        datetimestamp = datetime.now()
        with open('history.txt', 'a+') as f:
            f.write(f'{datetimestamp}: {os.getlogin()} failed to logged in\n')
        return "failure", key
    
#search function, search unencrypted secret keys and return the matches
def search():
    query = input('Enter your search: ')
    lines = []
    if len(query) != 0:
        with open('secrets.txt', 'r') as f:
            for line in f.readlines():
                if query in line.split('=', 1)[0]:
                    lines.append(line)
        if len(lines) == 0:
                print('No match found...')
        else:
            print('\nResults:\n--------')
            for line in lines:
                print(line.split('=', 1)[0])
            print('--------\n')
    else:
        print('\nResults:\n--------')
        with open('secrets.txt', 'r') as f:
            for line in f.readlines():
                print(line.split('=', 1)[0])
        print('--------\n')
        print('**No input, returned all entries.**')

# select desired secret by key (must be a match)
def decrypt(key):
    query = input('Enter your selection: ')
    lines = []
    # key = bytes(input('Paste your key: ').encode('utf-8'))
    if len(query) != 0:
        with open('secrets.txt', 'r') as f:
            for line in f.readlines():
                if query == line.split('=', 1)[0]:
                    lines.append(line)
        if len(lines) > 1:
            print('\nResults:\n--------\n')
            for line in lines:
                print(line)
            print('--------')
            print('\n**Multiple possible selections, please be more specific...**')
        elif len(lines) == 0:
            print('**No match found...**')
        else:
            fernet = Fernet(key)
            print('\nResult:\n--------')
            for line in lines:
                title = line.split('=', 1)[0]
                secret = line.split('=', 1)[1]
                decrypted_secret = fernet.decrypt(secret)
                print(title + '=' + secret + '\n--------\n')
                datetimestamp = datetime.now()
                with open('history.txt', 'a+') as f:
                    f.write(f'{datetimestamp}: {os.getlogin()} decrypted {line}')
            pyperclip.copy(decrypted_secret.decode())
            print('**Decrypted secret copied to clipboard successfully**\n')
    else:
        print('\nResults:\n--------')
        with open('secrets.txt', 'r') as f:
            for line in f.readlines():
                print(line.split('=', 1)[0])
        print('--------')
        print('\n**No selection specified. Please try again...**')

# add desired secret (key must be unique)
def add(key):
    while True:
        title = input('Enter the title of your new secret: ')
        if '=' in title:
            title = input('\n**Error: Cannot have "=" in the title**\nPlease enter a new title for your secret: ')
            continue
        else:
            with open('secrets.txt', 'r') as f:
                for line in f.readlines():
                    if title.lower() == line.lower().split('=', 1)[0]:
                        print('\nResults:\n--------')
                        print(line.split('=', 1)[0])
                        print('--------')

                        title = input('\n**Error: An entry with that title already exists**\nPlease enter a new title for your secret: ')    
                        Continue
                secret = bytes(getpass.getpass('Enter your new secret: ').encode('utf-8'))
                break


    # password = PASSWORD
    # print(password)
    # key = bytes(input('Paste your key: ').encode('utf-8'))

    fernet = Fernet(key)
    encrypted_secret = fernet.encrypt(secret)
    # fernet = Fernet(base64.urlsafe_b64encode(bytes('12345678901234567890'.encode('utf-8'))))
    # encrypted_secret = fernet.encrpyt(secret)
    with open('secrets.txt', 'a+') as f:
        f.write(title + '=' + str(encrypted_secret.decode()) + '\n')
    print('\nSuccessfully added the following entry:')
    print('----')
    print(title + '=' + str(encrypted_secret.decode()))
    print('----')
    datetimestamp = datetime.now()
    with open('history.txt', 'a+') as f:
        f.write(f'{datetimestamp}: {os.getlogin()} added {title}={str(encrypted_secret.decode())}\n')

# delete an entry
def delete():
    query = input('Enter your selection: ')
    lines = []
    # key = bytes(input('Paste your key: ').encode('utf-8'))
    if len(query) != 0:
        with open('secrets.txt', 'r') as f:
            for line in f.readlines():
                if query == line.split('=', 1)[0]:
                    lines.append(line.split('=', 1)[0])
        if len(lines) > 1:
            print('\nResults:\n--------')
            for line in lines:
                print(line)
            print('--------\n')
            print('**Multiple possible selections, please be more specific...**')
        elif len(lines) == 0:
            print('**No match found...**')
        else:
            data = ''
            for line in lines:
                with open('secrets.txt' , 'r+') as f:
                    for i in f.readlines():
                        if i.split('=', 1)[0] != line:
                            data = data + '\n' + i
                with open('secrets.txt', 'w') as f:
                    f.writelines(data.strip() + '\n')
                print('\nSuccessfully deleted the following entry:')
                print('----')
                print(line)
                print('----')
                datetimestamp = datetime.now()
                with open('history.txt', 'a+') as f:
                    f.write(f'{datetimestamp}: {os.getlogin()} deleted {line}\n')

    else:
        print('\nResults:\n--------')
        with open('secrets.txt', 'r') as f:
            for line in f.readlines():
                print(line)
        print('--------\n')
        print('**No selection specified. Please try again...**')

#clear clipboard
def clear_clipboard():
    pyperclip.copy('')
    print('\n**Clipboard clear...**')

# main function run with password login
def run():
    if not os.path.exists('history.txt'):
        open('history.txt', 'w')

    if os.path.exists('master_secret.txt'):
        Continue
    else:
        gen_main_secret()

    if not os.path.exists('secrets.txt'):
        open('secrets.txt', 'w')


    status, key = authenticate()
    while True:
        if status == 'success':
            print('\n**Successful login!**')
            print('''
Commands:
\tsearch\t\tSearch secrets
\tdecrypt\t\tDecrypt secret
\tadd\t\tAdd new secret
\tdelete\t\tDelete secret
\tclear\t\tClear clipboard
\thelp\t\tDisplay commands
\texit\t\tExit application''')
            while True:
                selection = input('''
> ''')
                if selection != '1' and \
                    selection.lower() != 'search' and \
                    selection != '2' and \
                    selection.lower() != 'decrypt'  and \
                    selection != '3' and \
                    selection.lower() != 'add' and \
                    selection != '4' and \
                    selection != '5' and \
                    selection.lower() != 'clear' and \
                    selection.lower() != 'delete' and \
                    selection.lower() != 'exit' and \
                    selection.lower() != 'help':
                    print('Bad selection! Try again...')
                elif selection == '1' or selection.lower() == 'search':
                    search()
                elif selection == '2' or selection.lower() == 'decrypt':
                    decrypt(key)
                elif selection == '3' or selection.lower() == 'add':
                    add(key)
                elif selection == '4' or selection.lower() == 'delete':
                    delete()
                elif selection == '5' or selection.lower() == 'clear':
                    clear_clipboard()
                elif selection == '6' or selection.lower() == 'help':
                    print('''
Commands:
\tsearch\t\tSearch secrets
\tdecrypt\t\tDecrypt secret
\tadd\t\tAdd new secret
\tdelete\t\tDelete secret
\tclear\t\tClear clipboard
\thelp\t\tDisplay commands
\texit\t\tExit application''')
                elif selection == '7' or selection.lower() == 'exit':
                    exit()

        else:
            print('**Failure!** \n**Incorrect Password... Please try again.**\n')
            return


if __name__ == '__main__':
    run()

