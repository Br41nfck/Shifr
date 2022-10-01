import re


def password_check(password):
    if len(password.get()) >= 8:
        if bool(re.match('((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,30})', password.get())):
            return "password is strong"
        elif bool(re.match('((\d*)([a-z]*)([A-Z]*)([!@#$%^&*]*).{8,30})', password.get())):
            return "password is weak. Try add specific symbols"
    else:
        return "You have entered an invalid password (less 8 symbols). Try again"
