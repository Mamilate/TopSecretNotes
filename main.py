import tkinter
from tkinter import messagebox
from tkinter import BOTH,END,LEFT
import base64

#apply cryptography with vigenere ciphher
#https://stackoverflow.com/a/38223403

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

window = tkinter.Tk()
window.title("Top Secret")
window.minsize(400,750)

def save_encrypt():
    title = my_title_entry.get()
    message = my_secret_text.get("1.0",END)
    master_secret = my_master_key_entry.get()

    if title =="" or message =="" or master_secret =="":
        messagebox.showinfo(title= "Error", message="Please enter all info!")

    else:
        message_encrypted = encode(master_secret,message)
        try:
            with open("my_secret.txt","a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("my_secret.txt","w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            my_title_entry.delete(0,END)
            my_master_key_entry.delete(0,END)
            my_secret_text.delete("1.0",END)

def decrypt_notes():
    message_decrypted = my_secret_text.get("1.0",END)
    master_secret = my_master_key_entry.get()

    if message_decrypted=="" or master_secret=="":
        messagebox.showinfo(title="Error!",message="Please enter all info")
    else:
        try:
            decrypted_message = decode(master_secret,message_decrypted)
            my_secret_text.delete("1.0",END)
            my_secret_text.insert("1.0",decrypted_message)
        except:
            messagebox.showinfo(title="Error!",message="Enter encrypted message")


photo = tkinter.PhotoImage(file="img_2.png")
photo_input = tkinter.Label(image=photo, width=200,height=200)
photo_input.pack()

my_title = tkinter.Label(text="Enter your title")
my_title.pack()


my_title_entry = tkinter.Entry()
my_title_entry.pack()

my_secret = tkinter.Label(text="Enter your secret")
my_secret.pack()

my_secret_text = tkinter.Text(width=20,height=20)
my_secret_text.pack()

my_master_key = tkinter.Label(text="Enter master key")
my_master_key.pack()

my_master_key_entry = tkinter.Entry()
my_master_key_entry.pack()

my_encrypt_button = tkinter.Button(text="Save&Encrypt",command=save_encrypt)
my_encrypt_button.pack()

my_decrypt_button = tkinter.Button(text="Decrypt",command=decrypt_notes)
my_decrypt_button.pack()



window.mainloop()