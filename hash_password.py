import hashlib
import argparse
import bcrypt
import sys

parser = argparse.ArgumentParser(description="Script för att hasha lösenord")

parser.add_argument("--password", type=str, required=True, help="Skriv lösenordet du vill hasha")
parser.add_argument("--algorithm", choices=["bcrypt", "md5", "scrypt", "sha256"], type=str, required=True, help="Välj vilken hash algorithm du vill använda")

args, unknown_args = parser.parse_known_args()

#Kontrollera okända argument
if unknown_args:
    print(f"Okända argument angavs: {', '.join(unknown_args)}")
    sys.exit(1)

#Försök att hasha lösenordet till relevant hash
#Error hantering
try:
    if args.algorithm == "bcrypt":
        hashed_password = bcrypt.hashpw(args.password.encode(), bcrypt.gensalt())
        print(f"Hashad lösenord: {hashed_password.decode()}")
        
        with open("passwords.txt", "a") as password_file:
            password_file.write(args.password + "\n")
        with open("bcrypt_hashes.txt", "a") as hash_file:
            hash_file.write(hashed_password.decode() + "\n")
            print(len((hashed_password.decode())))

    elif args.algorithm == "md5":
        hashed_password = hashlib.md5(args.password.encode()).hexdigest()
        print(f"Hashad lösenord: {hashed_password}")

        with open("passwords.txt", "a") as password_file:
            password_file.write(args.password + "\n")
        with open("md5_hashes.txt", "a") as hash_file:
            hash_file.write(hashed_password + "\n")

    elif args.algorithm == "sha256":
        hashed_password = hashlib.sha256(args.password.encode()).hexdigest()
        print(f"Hashad lösenord: {hashed_password}")

        with open("passwords.txt", "a") as password_file:
            password_file.write(args.password + "\n")
        with open("sha256_hashes.txt", "a") as hash_file:
            hash_file.write(hashed_password + "\n")

    elif args.algorithm == "scrypt":
        hashed_password = hashlib.scrypt(args.password.encode(), salt=b'some_salt', n=16384, r=8, p=1).hex()
        print(f"Hashad lösenord: {hashed_password}")

        with open("passwords.txt", "a") as password_file:
            password_file.write(args.password + "\n")
        with open("scrypt_hashes.txt", "a") as hash_file:
            hash_file.write(hashed_password + "\n")
#Error meddelanden
except ValueError as e:
    print(f"Ett värdefel inträffade vid hashing av lösenordet: {e}")
except Exception as e:
    print(f"Ett oväntat fel inträffade: {e}")