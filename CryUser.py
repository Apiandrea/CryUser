from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
import base64 as b64
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
import os
import datetime
from PIL import Image, ImageTk
from tkinter import filedialog as fd

window = tk.Tk()
window.geometry("300x450")
window.title("  CryUser -- By Apiandrea")
window.configure(background="gray")
window.resizable(False, False)

intro = tk.Label(text = "CHOOSE THE SYSTEM", font=("Helvetica", 16))
intro.grid(column = 0, row = 0, padx = 75, pady=20)

warning = tk.Label(text = "WARNING!\nBefore using the encrypt function save a\ncopy of the file that you want to encrypt", bg="white")

# SNIPPET FOR SELECTING THE FILE
def select_file():
    window.filename = fd.askopenfilename(title = "Choose the file", initialdir="/home")

open_button = tk.Button(window, text="Choose the file", command=select_file)
open_button.grid(column=0, row=1, pady=10)

def AES_clicked():
    print(window.filename)
    intro.destroy()
    introduce = tk.Label(text = "AES selected", font=("Helvetica", 16))
    introduce.grid(column = 0, row = 0, padx = 100, pady=20)
    AES_button.destroy()
    RSA_button.destroy()

    def ENC_clicked():
        with open(window.filename, "rb") as f:
            data = f.read()
        key = get_random_bytes(16)
        print(key)

        with open(window.filename + "_aeskey.txt", "wb") as f:
            f.write(key)

        cipher = AES.new(key, AES.MODE_CBC)
        e_data = cipher.encrypt(pad(data, AES.block_size))

        with open(window.filename, "wb") as f:
            f.write(cipher.iv)
            f.write(e_data)

    def DEC_clicked():
        with open(window.filename, "rb") as f:
            iv = f.read(16)
            data = f.read()
        key_name = window.filename + "_aeskey.txt"
        with open(key_name, "rb") as f:
            key = f.read(16)
        dec = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_data = unpad(dec.decrypt(data), AES.block_size)

        with open(window.filename, "wb") as f:
            f.write(decrypted_data)

    ENC_button = tk.Button(window, text="ENC", bg = "white", command = ENC_clicked, font=("Helvetica", 16))
    ENC_button.grid(column=0, row=2)
    DEC_button = tk.Button(window, text="DEC", bg = "white", command = DEC_clicked, font=("Helvetica", 16))
    DEC_button.grid(column=0, row=3)

AES_button = tk.Button(window, text="AES",bg = "white", command=AES_clicked, font=("Helvetica", 16))
AES_button.grid(column=0, row=2)

def RSA_clicked():
    print(window.filename)
    intro.destroy()
    introduce = tk.Label(text = "RSA selected", font=("Helvetica", 16))
    introduce.grid(column = 0, row = 0, padx=100, pady=20)
    AES_button.destroy()
    RSA_button.destroy()

    def ENC_clicked():
        with open(window.filename, "rb") as f:
            data = f.read()
        key = RSA.generate(2048)

        with open(window.filename + "_rsakey.pem", "wb") as f:
            f.write(key.export_key("PEM"))
        f = open(window.filename + "_rsakey.pem", "r")
        key = RSA.importKey(f.read())
        f.close()

        cipher = PKCS1_v1_5.new(key)
        c_text = cipher.encrypt(data)

        with open(window.filename, "wb") as f:
            f.write(c_text)

    def DEC_clicked():
        with open(window.filename, "rb") as f:
            data = f.read()

        with open(window.filename + "_rsakey.pem", "rb") as f:
            key = f.read()

        print(len(data))
        privKey = RSA.importKey(key)
        decipher = PKCS1_v1_5.new(privKey)
        dec_data = decipher.decrypt(data, sentinel=None)
        with open(window.filename, "wb") as f:
            f.write(dec_data)
        print(len(window.filename))

    ENC_button = tk.Button(window, text="ENC", bg="white", command=ENC_clicked, font=("Helvetica", 16))
    ENC_button.grid(column = 0, row = 2)
    DEC_button = tk.Button(window, text="DEC", bg = "white", command = DEC_clicked, font=("Helvetica", 16))
    DEC_button.grid(column=0, row=3)

AES_button = tk.Button(window, text="AES",bg = "white", command=AES_clicked, font=("Helvetica", 16))
AES_button.grid(column=0, row=2)
RSA_button = tk.Button(window, text="RSA",bg = "white", command=RSA_clicked, font=("Helvetica", 16))
RSA_button.grid(column=0, row=3)

warning.grid(column=0, row=4)



window.mainloop()
