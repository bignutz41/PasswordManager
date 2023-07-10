import base64
import hashlib
import json
import pyperclip
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import random

def main():
    welcome = '''

        Welcome to Password Manager!!!

        (1) Save password
        (2) Load password
        (3) Generate password
        (q) Quit

        '''
    done = False

    while done == False:
        choice = input(welcome)

        if choice == '1':
            mp = getpass("Enter master password:")
            sitename = input("Enter sitename:")
            password = getpass("Enter password:")
            key = generate_key(mp)
            encrypted_pass = encrypt_password(password, key)
            save_password(sitename, encrypted_pass)
            print("Password saved!!")
        elif choice == '2':
            mp = getpass("Enter master password:")
            sitename = input("Enter sitename:")
            encrypted_pass = retrieve_password(sitename)
            key = generate_key(mp)
            decrypted_pass = decrypt_password(encrypted_pass, key)
            pyperclip.copy(decrypted_pass)
            print("Password copied!!")
        elif choice == '3':
            password = generate_password()
            pyperclip.copy(password)
            print("Password Copied!!")
        elif choice == 'q':
            done = True
        else:
            print("Invalid Input!!!")


def generate_key(password):

    with open('salt.key', 'r') as file:
        salt = file.read()
        salt_bytes = bytes(salt, 'utf-8')
        file.close()
    
    hashed_pass = hashlib.sha256(password.encode()).hexdigest().encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=10000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(hashed_pass))
    
    return key

def generate_password():

    password = ''
    options = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM!@#$%^&*"

    for i in range(26):
        letter = random.choice(options)
        password += letter

    return password

def save_password(sitename, password):

        temp = {}

        with open('passwords.json', 'r') as f:
            temp = json.load(f)
        
        if sitename not in temp.keys():
            temp[sitename] = password

            with open('passwords.json', 'w') as f:
                json.dump(temp, f)

        else:
            print("This sitename already exists")

        f.close()
        

def encrypt_password(password, key):

    password_bytes = password.encode()
    f = Fernet(key)

    encrypted_password = f.encrypt(password_bytes)

    return encrypted_password.decode()

def decrypt_password(encrypted_password, key):
    try:
        decrypted_password = Fernet.decrypt(Fernet(key), token=encrypted_password).decode()
        return decrypted_password
    except:
        print("Incorrect master password :(")
        
        return '8===D'
def retrieve_password(sitename):
    temp = {}

    with open('passwords.json', 'r') as f:
        temp = json.load(f)

    password = temp[sitename]

    return password

if __name__ == '__main__':
    main()
