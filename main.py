# Version 0.0.5
# Last update: 01.10.2022
from tkinter import *
from tkinter import ttk

from Algs.check_strong import password_check
from Algs.create_email_and_password import start
# Internal functions
from Algs.encode_decode import encode, decode
from Algs.md5 import md5_crypt
from Algs.reverse_string import reverse
from Algs.sha1 import sha1_crypt
from Algs.sha2 import sha2_512_crypt
from Algs.sha3 import sha3_512_crypt

# Consts
root = Tk()
width = 0
height = 0

root.title("Shifr - message encryption and decryption")
root.resizable(False, False)
notebook = ttk.Notebook(root)
notebook.pack()

# Frames
crypto_frame = Frame(notebook, width = width, height = height)
password_frame = Frame(notebook, width = width, height = height)

crypto_frame.pack(fill = BOTH)
password_frame.pack(fill = BOTH)

notebook.add(crypto_frame, text = "Cryptography")
notebook.add(password_frame, text = "Password")

# Vars
rand = StringVar()
rvrs = StringVar()
Msg = StringVar()
key = StringVar()
mode = StringVar()
result = StringVar()
sha_1 = StringVar()
sha_2_512 = StringVar()
sha3_512 = StringVar()
md5 = StringVar()
password = StringVar()
mail = StringVar()


# Function to reset options
def reset():
    rand.set("")
    Msg.set("")
    key.set("")
    mode.set("")
    result.set("")
    rvrs.set("")
    sha_1.set("")
    sha_2_512.set("")
    sha3_512.set("")
    md5.set("")
    password.set("")
    lbl_chk['text'] = "Check"


# Labels
lblInfo = Label(crypto_frame, text = "Message Encrypt/Decrypt\n")
lblInfo.pack()

# Message
lbl_Msg = Label(crypto_frame, text = "Message")
lbl_Msg.pack()

txt_Msg = Entry(crypto_frame, textvariable = Msg, insertwidth = 4)
txt_Msg.pack(ipadx = 100)

# Key
lbl_key = Label(crypto_frame, text = "Keyword")
lbl_key.pack()

txt_key = Entry(crypto_frame, textvariable = key, insertwidth = 4)
txt_key.pack()

# Mode
lbl_mode = Label(crypto_frame, text = "Mode (e - encrypt, d - decrypt)")
lbl_mode.pack()

txt_mode = Entry(crypto_frame, textvariable = mode, insertwidth = 4)
txt_mode.pack()

# Result
lbl_res = Label(crypto_frame, text = "Result")
lbl_res.pack()

txt_res = Entry(crypto_frame, textvariable = result, insertwidth = 4)
txt_res.pack(ipadx = 100)

# Revert String
lbl_rvrs = Label(crypto_frame, text = "Reverse")
lbl_rvrs.pack()

txt_rvrs = Entry(crypto_frame, textvariable = rvrs, insertwidth = 4)
txt_rvrs.pack(ipadx = 100)

# SHA-1
lbl_sha_1 = Label(crypto_frame, text = "SHA-1")
lbl_sha_1.pack()

txt_sha_1 = Entry(crypto_frame, textvariable = sha_1, insertwidth = 4)
txt_sha_1.pack(ipadx = 100)

# SHA-2
lbl_sha2_512 = Label(crypto_frame, text = "SHA-2")
lbl_sha2_512.pack()

txt_sha2_512 = Entry(crypto_frame, textvariable = sha_2_512, insertwidth = 4)
txt_sha2_512.pack(ipadx = 350)

# SHA-3
lbl_sha3_512 = Label(crypto_frame, text = "SHA-3")
lbl_sha3_512.pack()

txt_sha3_512 = Entry(crypto_frame, textvariable = sha3_512, insertwidth = 4)
txt_sha3_512.pack(ipadx = 350)

# MD5
lbl_md5 = Label(crypto_frame, text = "MD5")
lbl_md5.pack()

txt_md5 = Entry(crypto_frame, textvariable = md5, insertwidth = 4)
txt_md5.pack(ipadx = 100)

# Check pass
lbl_pass = Label(password_frame, text = "Check password")
lbl_pass.pack()

lbl_chk = Label(password_frame, text = "Check")
lbl_chk.pack()

txt_pass = Entry(password_frame, textvariable = password, insertwidth = 4)
txt_pass.pack(ipadx = 100)


def check():
    lbl_chk['text'] = password_check(password)


# Check
b_check = Button(password_frame, text = "Check", command = check)
b_check.pack()

# Create email and password
lbl_email_n_pass = Label(password_frame, text = "Create email and pass")
lbl_email_n_pass.pack()

txt_email_n_pass = Text(password_frame, width = 60, height = 2)
txt_email_n_pass.pack()

# Clipboard
lbl_clpbrd = Label(crypto_frame, text = "Clipboard")
lbl_clpbrd.pack()

clipboard = Text(crypto_frame, width = 150, height = 8)
clipboard.pack()


# Info messages
def callback():
    try:
        msg = Msg.get()
        res = result.get()
        rvrs.set(reverse(msg))
        sha_1.set(sha1_crypt(msg))
        sha_2_512.set(sha2_512_crypt(msg))
        sha3_512.set(sha3_512_crypt(msg))
        md5.set(md5_crypt(msg))

        sha1_msg = "SHA-1:" + sha1_crypt(msg) + '\n'
        sha2_msg = "SHA-2:" + sha2_512_crypt(msg) + '\n'
        sha3_msg = "SHA-3:" + sha3_512_crypt(msg) + '\n'
        md5_msg = "MD5:" + md5_crypt(msg) + '\n'
        reverse_msg = "Reverse:" + reverse(msg) + '\n'
        message_msg = "Message:" + msg + '\n'
        key_msg = "Key:" + key.get() + '\n'
        result_msg = "Result:" + res + '\n'
        clipboard.insert('1.0', '#' * 134 + '\n')
        clipboard.insert('1.0', md5_msg)
        clipboard.insert('1.0', sha3_msg)
        clipboard.insert('1.0', sha2_msg)
        clipboard.insert('1.0', sha1_msg)
        clipboard.insert('1.0', reverse_msg)
        clipboard.insert('1.0', key_msg)
        clipboard.insert('1.0', result_msg)
        clipboard.insert('1.0', message_msg)

        clear = msg
        k = key.get()
        m = mode.get()
        if m == 'e':
            result.set(encode(k, clear))
        else:
            result.set(decode(k, clear))

    except Exception as e:
        f = open('logs.log', 'a')
        f.write(str(e) + '\n')
        f.close()


def delete():
    clipboard.delete(1.0, END)


# Buttons

# Ok
ok_b = Button(crypto_frame, text = "OK", command = callback)
ok_b.pack(side = LEFT)

# Reset
reset_b = Button(crypto_frame, text = "Reset", command = reset)
reset_b.pack(side = TOP)

# Exit
exit_b = Button(root, text = "Exit", command = root.destroy)
exit_b.pack(side = RIGHT)


def save_to_file_crypto():
    with open('output.txt', 'a') as out:
        out.write("Result:" + result.get() + '\n')
        out.write("Message:" + Msg.get() + '\n')
        out.write("Key:" + key.get() + '\n')
        out.write("Reverse:" + reverse(Msg.get()) + '\n')
        out.write("SHA-1:" + sha1_crypt(Msg.get()) + '\n')
        out.write("SHA-2:" + sha2_512_crypt(Msg.get()) + '\n')
        out.write("SHA-3:" + sha3_512_crypt(Msg.get()) + '\n')
        out.write("MD5:" + md5_crypt(Msg.get()) + '\n')
        out.write('#' * 134 + '\n')
        print("Codes will be successfully added to file 'output.txt'.")
        out.close()


# Save Crypto result to file
save_crypt_b = Button(crypto_frame, text = "Save", command = save_to_file_crypto)
save_crypt_b.pack()


def email_pass():
    txt_email_n_pass.delete(1.0, END)
    email_n_pass = start()
    txt_email_n_pass.insert(1.0, email_n_pass)


def save_to_file_email_pass():
    out_str = txt_email_n_pass.get(1.0, END)
    with open('email_and_pass.txt', 'a') as out:
        out.write(out_str)
    out.close()


# Create
create_b = Button(password_frame, text = "Create", command = email_pass)
create_b.pack()

# Save email and pass to file
save_email_pass_b = Button(password_frame, text = "Save", command = save_to_file_email_pass)
save_email_pass_b.pack()

# Clear clipboard
b_clear_clpbrd = Button(crypto_frame, text = "Clear", command = delete)
b_clear_clpbrd.pack()

# Driver
root.mainloop()
