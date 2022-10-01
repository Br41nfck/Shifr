# MD5 (Message Digest 5) Python Implementation
# NO KEY, but u may crypt most popular words and check difference between
import hashlib


# Crypt by md5
def md5_crypt(message):
    msg = hashlib.md5(message.encode())
    return msg.hexdigest()
    # return "Message:", message, "\nMD5:", Msg.hexdigest()


# Using:
# ans = md5_crypt("Hello world!")
# print(ans)
