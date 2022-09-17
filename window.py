# Version 0.0.1
# Last update: 17.09.2022

from tkinter import *
import base64

root = Tk()

root.geometry("540x180")
root.title("Shifr - message encryption and decryption")
root.resizable(False, False)

Tops = Frame(root, width = 1600, relief = SUNKEN)
Tops.pack(side = TOP)

f1 = Frame(root, width = 800, height = 700, relief = SUNKEN)
f1.pack(side = LEFT)

lblInfo = Label(Tops, text = "Message Encrypt/Decrypt \n", anchor = 'w')
lblInfo.grid(row = 1, column = 0)

rand = StringVar()
Msg = StringVar()
key = StringVar()
mode = StringVar()
Result = StringVar()


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


# labels
lblMsg = Label(f1, text = "Message", anchor = "w")
lblMsg.grid(row = 1, column = 0)

txtMsg = Entry(f1, textvariable = Msg, insertwidth = 4)
txtMsg.grid(row = 1, column = 1)

lbl_key = Label(f1, text = "Key", bd = 16, anchor = "w")
lbl_key.grid(row = 2, column = 0)

txt_key = Entry(f1, textvariable = key, insertwidth = 4)
txt_key.grid(row = 2, column = 1)

lbl_mode = Label(f1, text = "Mode (e - encrypt, d - decrypt)", anchor = "w")
lbl_mode.grid(row = 3, column = 0)

txt_mode = Entry(f1, textvariable = mode, insertwidth = 4)
txt_mode.grid(row = 3, column = 1)

lblService = Label(f1, text = "Result", anchor = "w")
lblService.grid(row = 2, column = 3)

txtService = Entry(f1, textvariable = Result, insertwidth = 4)
txtService.grid(row = 2, column = 4)


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
    print("Message = ", (Msg.get()))
    clear = Msg.get()
    k = key.get()
    m = mode.get()
    if m == 'e':
        Result.set(encode(k, clear))
    else:
        Result.set(decode(k, clear))


# Show message button
btnTotal = Button(f1, text = "Show Message", command = callback)
btnTotal.grid(row = 4, column = 1)

# Reset button
btnReset = Button(f1, text = "Reset", command = reset)
btnReset.grid(row = 4, column = 2)

# Exit button
btnExit = Button(f1, text = "Exit", command = qexit)
btnExit.grid(row =4, column = 3)

# keeps window alive
root.mainloop()
