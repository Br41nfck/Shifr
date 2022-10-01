# SHA-2 (Secure Hash Algorithm Version 2) Python Implementation
# NO KEY, but u may crypt most popular words and check difference between
import hashlib


# Crypt by sha-2
def sha2_512_crypt(message):
    msg = hashlib.sha512(message.encode())
    return msg.hexdigest()
    # return "Message:", message, "\nSHA-2:", Msg.hexdigest()


# Using:
# ans = sha2_crypt("Hello world!")
# print(ans)
