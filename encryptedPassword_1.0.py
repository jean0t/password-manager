from cryptography.fernet import Fernet
import sqlite3 as sql
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path
from sys import exit
from os import system
from time import sleep
from pwinput import pwinput


# ask for a valid password without spaces
def ask_password(hide=False) -> str:
    if hide:   
        while True:
            password = pwinput(prompt= "Type the password: ", mask= "?").strip() # ask for a word that is the password
            if len(password) <= 5 or (" " in password):
                print("Create a stronger password with 6-50 characters and without spaces")
            elif len(password) > 50 or (" " in password):
                print("Too long, make it shorter, length accepted is 6-50 and without spaces")
            else:
                break

        return password #return the password treated in case of spaces
    else:
        while True:
            password = input("Password: ").strip() # ask for a word that is the password
            if len(password) <= 5 or (" " in password):
                print("Create a stronger password with 6-50 characters and without spaces")
            elif len(password) > 50 or (" " in password):
                print("Too long, make it shorter, length accepted is 6-50 and without spaces")
            else:
                break

        return password #return the password treated in case of spaces

# functions to cryptography
def derive_key(password : str) -> bytes: # transform the password in a particular key according to the characters
    password = password.encode()
    salt = b'2\x9e\xc8\x9d\xae\x8b]  \x07\xca\x94x\xc5\xd0\x97'

    kdf = PBKDF2HMAC(
        algorithm= hashes.SHA256(),
        length=32,
        salt= salt,
        iterations= 500000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))

    return key # return the key to be used in the process of encrypt and decrypt

# key = bytes; message = string; returns an encoded message in strings
def encrypt(key: bytes, message: str) -> str:
    f = Fernet(key= key)
    encrypted_message = f.encrypt(message.encode())

    return encrypted_message.decode()

def decrypt(key: bytes, message: str) -> str:
    f = Fernet(key= key)
    decrypted_message = f.decrypt(message.encode())

    return decrypted_message.decode()

# functions to interact with the database

def starting_db(): #creating the database in case it doesnt exists
    database = sql.connect("passwords.db")
    cursor = database.cursor()
    cursor.execute("CREATE TABLE personal_passwords(App, Password, Username, id)")
    database.commit()
    cursor.close()
    database.close()

def number_id() -> int: # get the actual number of id to get the correct position in the table
    database = sql.connect("passwords.db")
    cursor = database.cursor()
    numberId = cursor.execute("SELECT count(*) FROM personal_passwords")
    number_Id = int(numberId.fetchone()[0]) # just for security
    cursor.close()
    database.close()

    return number_Id

def adding_passwd(key: bytes, app: str, passwd: str, username= " "): # adding new password that the user might want to keep safe
    database = sql.connect("passwords.db")
    cursor = database.cursor()
    id = str(number_id())
    cursor.execute("INSERT INTO personal_passwords(App, Password, Username, id) VALUES (?, ?, ?, ?)", (encrypt(key, app), encrypt(key, passwd), encrypt(key, username), encrypt(key, id)))
    database.commit()
    cursor.close()
    database.close()
    system("clear")

def verifying_password(key):
    database = sql.connect("passwords.db")
    cursor = database.cursor()
    # try:
        # will test if the password was correct to show the database
    get_id = cursor.execute("SELECT id FROM personal_passwords")
    first_id = get_id.fetchone()
    if first_id is None:
        print("Since it is your first time, the password you entered will be stored as the password ")
        cursor.execute("INSERT INTO personal_passwords(id) VALUES (?)", [encrypt(key= key, message= '0')])
        database.commit()
        print("Your password was saved, keep it safe and do not forget")
        cursor.close()
        database.close()
        return
        
    else:
        first_id = decrypt(key= key, message= str(first_id[0]))
        id = int(first_id) # if the password is correct it will be converted to int
        if isinstance(id, int):
            return "ok"
        else:
            print("You didnt't put the correct password")
            print("the program will close...")
            sleep(2)
            exit()
    # except ValueError:
    #     print("An error occurred\nLeaving the software...")
    #     sleep(2)

def deleting_passwd(key: bytes, id: str): # deleting an existing password
    database = sql.connect('passwords.db')
    cursor = database.cursor()
    db_id = encrypt(key= key, message= id)
    cursor.execute("DELETE FROM personal_passwords WHERE id = (?)", [db_id])

    confirmation = input("Are you sure?\n[y/n]: ").lower().strip()
    if confirmation in ["y", "yes"]:
        print("Data deleted")
        database.commit()
        cursor.close()
        database.close()
    else:
        print("Data wasn't deleted")
        cursor.close()
        database.close()

def show_passwd(key:bytes): # showing all the passwords stored in the database
    f = Fernet(key) # necessary to decrypt and show the data correctly from the database
    database = sql.connect('passwords.db')
    cursor = database.cursor()
    passwds = cursor.execute("SELECT * FROM personal_passwords")
    passwds = passwds.fetchall()[1:]

    for item in passwds: # shows the itens in the database with identifiers to better visualization
        print("=" * 30)
        print(f"id [{decrypt(key= key, message= item[3])}]")
        print("App: ", decrypt(key= key, message=item[0]))
        print("Username: ", decrypt(key= key, message= item[2]))
        print("Password: ", decrypt(key= key, message= item[1]))
        print("=" * 30)

    input("Press enter to Exit")
    system("clear")
    cursor.close()
    database.close()
    


# main function with the organized code
def main():
    try:
        system("clear")
        path = Path()
        archive = path / "passwords.db"
        if not archive.exists():
            print("#"*60)
            print("Since it is your first time,\nwe are going to register a password/passphrase for you\nto keep the database safe for you\nto store your passwords")
            print("Next time your password will be concealed")
            passphrase = ask_password()
            starting_db()

        else:
            print("You need to put the password to access the registers in the database")
            print("If you don't put the right password, the registers won't appear for you")
            passphrase = ask_password(hide= True)
        
        system("clear")
        # asks for the passphrase to secure the data in the password
        key = derive_key(password= passphrase) # get the key from the passphrase
        verifying_password(key= key)

        while True:
            
            print("#"*30)
            print("What do you want to do?")
            print("[1] See the data stored")
            print("[2] Add new data")
            print("[3] Remove already added data")
            print("[4] Quit")
            option = int(input("-> "))
            
            match option:
                case 1:
                    system("clear")
                    show_passwd(key= key)
                case 2:
                    application = input("Application it will be used: ").strip().capitalize()
                    passwrd = ask_password()
                    username = input("Username (if not, just let blank): ")
                    adding_passwd(key= key,app= application, passwd= passwrd, username= username)
                case 3:
                    show_passwd(key= key)
                    id = input("Id of the item you want to delete: ").strip()
                    deleting_passwd(key= key, id= id)
                    system("clear")
                case 4:
                    system("clear")
                    exit()
                case _:
                    system("clear")
                    print("!!!Option doesn't exist!!!")
    except (TypeError, ValueError):
        print("An Error occurred, leaving the software...")
        sleep(1.5)


if __name__ == "__main__":
    main()