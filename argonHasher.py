import argon2
pwd = input("Password: ")
print(argon2.PasswordHasher().hash(pwd))