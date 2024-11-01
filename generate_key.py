from cryptography.fernet import Fernet
import argparse
import sys

#Generera en nyckel
key = Fernet.generate_key()

#Skapa parser för argument
parser = argparse.ArgumentParser(description="Script för att skapa en nyckel för kryptering och dekryptering")

parser.add_argument("key_name", type=str, help="Skriv in namnet på nyckeln du vill skapa")

args, unknown_args = parser.parse_known_args()

#Kontrollera okända argument
if unknown_args:
    print(f"Okända argument angavs: {', '.join(unknown_args)}")
    sys.exit(1)

# Kontrollera om filnamnet slutar på ".key", lägg till det annars
if not args.key_name.endswith(".key"):
    args.key_name += ".key"

#Försök att skriva nyckeln till fil
try:
    with open(args.key_name, "wb") as key_file:
        key_file.write(key)
    print(f"Nyckeln har sparats som {args.key_name}")
except IOError as e:
    print(f"Ett fel inträffade när nyckeln skulle sparas: {e}")
    exit()
except Exception as e:
    print(f"Ett oväntat fel inträffade: {e}")
    exit()