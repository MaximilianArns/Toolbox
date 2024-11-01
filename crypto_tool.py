from cryptography.fernet import Fernet, InvalidToken
import argparse
import os
import sys

#Funktion för att kontrollera om en fil existerar
def check_file_exists(file_path, description):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{description} '{file_path}' hittades inte. Kontrollera att filen existerar och försök igen.")

#Skapar parser arguments för användaren att använda när hen vill försöka kryptera eller dekryptera
parser = argparse.ArgumentParser(description="Script för att antingen kryptera eller dekryptera en filtext")

parser.add_argument("key_name", type=str, help="Ange vilken fil du vill använda som nyckel för att kryptera din text.")
parser.add_argument("file_name", type=str, help="Skriv namnet på filen som ska innehålla den krypterade texten")
parser.add_argument("--message", type=str, help="Skriv meddelandet du vill kryptera (endast för kryptering)")
parser.add_argument("--mode", choices=["kryptera", "dekryptera"], required=True, help="Välj att antingen kryptera eller dekryptera")

args, unknown_args = parser.parse_known_args()

#Kontrollera okända argument
if unknown_args:
    print(f"Okända argument angavs: {', '.join(unknown_args)}")
    sys.exit(1)


#Error hantering
try:
    #Kontrollera om nyckelfilen finns
    check_file_exists(args.key_name, "Nyckelfilen")

    #Kontrollera om filen finns för dekryptering
    if args.mode == "dekryptera":
        check_file_exists(args.file_name, "Filen som ska dekrypteras")

    #Krypterar filen
    if args.mode == "kryptera":
        if not args.message:
            parser.error("Krypteringsläget kräver att du anger ett meddelande med --message.")

        #Öppnar nyckeln
        with open(args.key_name, "rb") as key_file:
            key = key_file.read()
        
        #Försök att kryptera meddelandet
        try:
            cipher_suite = Fernet(key)
            message = args.message.encode()
            cipher_text = cipher_suite.encrypt(message)
            print(f"Krypterad text: {cipher_text}")
        except Exception as e:
            print(f"Fel vid kryptering: {e}")
            sys.exit(1)
        
        #Skriv krypterad text till fil
        try:
            with open(args.file_name, "wb") as encoded_file:
                encoded_file.write(cipher_text)
        except IOError:
            print(f"Kunde inte skriva till filen '{args.file_name}'. Kontrollera dina rättigheter.")
            sys.exit(1)

    #Dekrypterar filen
    elif args.mode == "dekryptera":
        try:
            #Läser in krypterad text från fil
            with open(args.file_name, "rb") as encoded_file:
                message = encoded_file.read()
        except IOError:
            print(f"Kunde inte läsa filen '{args.file_name}'. Kontrollera dina rättigheter.")
            sys.exit(1)

        #Läser in nyckeln
        with open(args.key_name, "rb") as key_file:
            key = key_file.read()

        #Försök att dekryptera texten med hjälp av nyckeln
        try:
            cipher_suite = Fernet(key)
            plain_text = cipher_suite.decrypt(message)
            print(f"Dekrypterad text: {plain_text.decode()}")
        except InvalidToken:
            print("Nyckeln matchar inte eller den krypterade texten är skadad.")
        except Exception as e:
            print(f"Ett oväntat fel inträffade vid dekryptering: {e}")
            sys.exit(1)

#Error meddelande
except FileNotFoundError as e:
    print(f"Fel: {e}")
except Exception as e:
    print(f"Ett oväntat fel inträffade: {e}")
    sys.exit(1)