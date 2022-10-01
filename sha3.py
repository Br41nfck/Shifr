# SHA-3 (Secure Hash Algorithm Version 3) Python Implementation
# NO KEY, but u may crypt most popular words and check difference between
import hashlib


# Crypt by sha-3
def sha3_512_crypt(message):
    msg = hashlib.sha3_512(message.encode())
    return msg.hexdigest()
    # return "Message:", message, "\nSHA-3:", Msg.hexdigest()


# Using:
# ans = sha3_crypt("Hello world!")
# print(ans)
