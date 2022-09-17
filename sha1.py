# SHA-1 (Secure Hash Algorithm Version 1) Python Implementation
# NO KEY, but u may crypt most popular words and check difference between
import hashlib


# Crypt by sha-1
def sha1_crypt(message):
    msg = hashlib.sha1(message.encode())
    return msg.hexdigest()
    #return "Message:", message, "\nSHA-1:", msg.hexdigest()


# Using:
# ans = sha1_crypt("Hello world!")
# print(ans)
