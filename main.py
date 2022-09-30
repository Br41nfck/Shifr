# Version 0.0.4
# Last update: 30.09.2022
# UPDATES:
# 1. Add SHA-2 and SHA-3 Algorithms
# 2. Write SHA's to file
# 3. Change WM
# 4. Minor Improvements
from tkinter import *
import base64

from Algs.reverse_string import reverse
from Algs.sha1 import sha1_crypt
from Algs.sha2 import sha2_512_crypt
from Algs.sha3 import sha3_512_crypt


# Config
root = Tk()
root.geometry("640x480")
root.title("Shifr - message encryption and decryption")
root.resizable(False, False)


# Vars
rand = StringVar()
rvrs = StringVar()
Msg = StringVar()
key = StringVar()
mode = StringVar()
Result = StringVar()
sha_1 = StringVar()
sha_2_512 = StringVar()
sha3_512 = StringVar()


# exit function
def qexit():
    root.destroy()


# Function to reset the window
def reset():
    rand.set("")
    Msg.set("")
    key.set("")
    mode.set("")
    Result.set("")
    rvrs.set("")
    sha_1.set("")
    sha_2_512.set("")
    sha3_512.set("")


# Labels
lblInfo = Label(root, text = "Message Encrypt/Decrypt \n", anchor = 'w')
lblInfo.grid(row = 0, column = 2)
# Message
lbl_Msg = Label(root, text = "Message", anchor = "w")
lbl_Msg.grid(row = 1, column = 0)

txt_Msg = Entry(root, textvariable = Msg, insertwidth = 4)
txt_Msg.grid(row = 1, column = 1)
# Key
lbl_key = Label(root, text = "Keyword", anchor = "w")
lbl_key.grid(row = 2, column = 0)

txt_key = Entry(root, textvariable = key, insertwidth = 4)
txt_key.grid(row = 2, column = 1)
# Mode
lbl_mode = Label(root, text = "Mode (e - encrypt, d - decrypt)", anchor = "w")
lbl_mode.grid(row = 3, column = 0)

txt_mode = Entry(root, textvariable = mode, insertwidth = 4)
txt_mode.grid(row = 3, column = 1)
# Result
lbl_res = Label(root, text = "Result", anchor = "w")
lbl_res.grid(row = 4, column = 0)

txt_res = Entry(root, textvariable = Result, insertwidth = 4)
txt_res.grid(row = 4, column = 1)
# Revert String
lbl_rvrs = Label(root, text = "Revert", anchor = "w")
lbl_rvrs.grid(row = 1, column = 3)

txt_rvrs = Entry(root, textvariable = rvrs, insertwidth = 4)
txt_rvrs.grid(row = 1, column = 4)
# SHA-1
lbl_sha_1 = Label(root, text = "SHA-1", anchor = "w")
lbl_sha_1.grid(row = 2, column = 3)

txt_sha_1 = Entry(root, textvariable = sha_1, insertwidth = 4)
txt_sha_1.grid(row = 2, column = 4)
# SHA-2
lbl_sha2_512 = Label(root, text = "SHA-2", anchor = "w")
lbl_sha2_512.grid(row = 3, column = 3)

txt_sha2_512 = Entry(root, textvariable = sha_2_512, insertwidth = 4)
txt_sha2_512.grid(row = 3, column = 4)

lbl_sha3_512 = Label(root, text = "SHA-3", anchor = "w")
lbl_sha3_512.grid(row = 4, column = 3)

txt_sha3_512 = Entry(root, textvariable = sha3_512, insertwidth = 4)
txt_sha3_512.grid(row = 4, column = 4)


# Function to encode
def encode(key_, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key_[i % len(key_)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


# Function to decode
def decode(key_, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key_[i % len(key_)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def callback():
    try:
        msg = Msg.get()
        rvrs.set(reverse(msg))
        sha_1.set(sha1_crypt(msg))
        sha_2_512.set(sha2_512_crypt(msg))
        sha3_512.set(sha3_512_crypt(msg))

        with open('output.txt', 'a') as out:
            out.write("Message:" + msg + '\n')
            out.write("Reverse:" + reverse(msg) + '\n')
            out.write("SHA-1:" + sha1_crypt(msg) + '\n')
            out.write("SHA-2:" + sha2_512_crypt(msg) + '\n')
            out.write("SHA-3:" + sha3_512_crypt(msg) + '\n')
            out.write('#' * 134 + '\n')
            print("Codes will be successfully added to file 'output.txt'.")
            out.close()

        clear = msg
        k = key.get()
        m = mode.get()
        if m == 'e':
            Result.set(encode(k, clear))
        else:
            Result.set(decode(k, clear))

    except Exception as e:
        f = open('logs.log', 'a')
        f.write(str(e)+'\n')
        f.close()

# Buttons


# Ok
ok_b = Button(root, text = "OK", command = callback)
ok_b.grid(row = 10, column = 1)


# Reset
reset_b = Button(root, text = "Reset", command = reset)
reset_b.grid(row = 10, column = 2)


# Exit
exit_b = Button(root, text = "Exit", command = root.destroy)
exit_b.grid(row = 10, column = 3)


# Keeps window alive
root.mainloop()
