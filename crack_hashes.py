import hashlib
import sys
import argparse
import bcrypt

#Skapar parser arguments för användaren att använda när hen vill försöka knäcka olika hashes
parser = argparse.ArgumentParser(description="Script för att knäcka hashade lösenord")

parser.add_argument("--mode", choices=["scan_file", "scan_a_hash"], type=str, required=True, help="Ange om du antingen vill knäcka en specifik hash eller försöka matcha hashes med lösenord från listor")
parser.add_argument("--hash", type=str, help="Ange vilken hash du vill försöka knäcka.")
parser.add_argument("--file", type=str, help="Ange vilken hash fil du vill försöka knäcka.")
parser.add_argument("wordlist", type=str, help="Skriv filnamnet med lösenorden du vill använda för att knäcka hashen")
parser.add_argument("algorithm", choices=["bcrypt", "md5", "sha256", "scrypt"], help="Ange algoritmen som användes för att skapa hashen")

args, unknown_args = parser.parse_known_args()

#Kontrollera okända argument
if unknown_args:
    print(f"Okända argument angavs: {', '.join(unknown_args)}")
    sys.exit(1)

#Kontrollera att rätt kombination av argument skickas beroende på `mode`
if args.mode == "scan_a_hash":
    if not args.hash:
        print("--hash-argumentet krävs för 'scan_a_hash'-läget.")
        sys.exit(1)
    elif args.file:
        print("--file-argumentet ska inte användas i 'scan_a_hash'-läget.")
        sys.exit(1)

elif args.mode == "scan_file":
    if not args.file:
        print("Fel: --file-argumentet krävs för 'scan_file'-läget.")
        sys.exit(1)
    elif args.hash:
        print("Fel: --hash-argumentet ska inte användas i 'scan_file'-läget.")
        sys.exit(1)


#Funktion för att knäcka en specifik hash
def crack_password(hashed_password, wordlist, algorithm):

    #Error hantering
    try:
        #Öppnar fil med lösenord och gå igenom varje rad/lösenord
        with open(wordlist, 'r') as file:

            #Samma salt och scrypt-parametrar som vid skapandet av scrypt-hashes. Måste anpassas efter hur scrypt-hashen som körs
            salt = b'some_salt'
            n = 16384
            r = 8
            p = 1
            
            #For loop för att gå igenom alla lösenord i listan och omvandla de till en specifik hash för att sedan jämföra med hashen man vill knäcka
            for line in file:
                word = line.strip()
                #Error hantering
                try:
                    if algorithm == "md5":
                        hashed_word = hashlib.md5(word.encode()).hexdigest()
                    elif algorithm == "sha256":
                        hashed_word = hashlib.sha256(word.encode()).hexdigest()
                    elif algorithm == "bcrypt":
                        #Bcrypt har ett annat sätt att jämföra hashes än vad de andra hashes har i denna kod
                        if bcrypt.checkpw(word.encode(), hashed_password.encode()):
                            print(f"Lösenord funnet: {word}")
                            return word
                        continue
                    elif algorithm == "scrypt":
                        hashed_word = hashlib.scrypt(word.encode(), salt=salt, n=n, r=r, p=p).hex()

                    #Kontrollera om lösenordens hash matchar vår sökta hash
                    if hashed_word == hashed_password:
                        print(f"Lösenord funnet: {word}")
                        return word
        
    #Olika error meddelanden nedanför
                except Exception as e:
                    print(f"Fel vid bearbetning av lösenord '{word}':", e)

        print("Lösenordet hittades inte i ordlistan.")
        return None
    except FileNotFoundError:
        print(f"Ordlistfilen '{wordlist}' hittades inte.")
    except IOError:
        print(f"Kunde inte läsa ordlistfilen '{wordlist}'.")
    except Exception as e:
        print("Ett oväntat fel inträffade vid uppläsning av ordlistan:", e)
    return None

#Funktion för att knäcka och matcha flera hashes och lösenord tillsammans från filer
def crack_all_hashes_in_file(hash_file, wordlist, algorithm):

    #Error hantering
    try:
        #Öppnar fil med hashes och går igenom varje rad/hash
        with open(hash_file, 'r') as file:

            #Samma salt och scrypt-parametrar som vid skapandet av scrypt-hashes. Måste anpassas efter hur scrypt-hashen som körs
            salt = b'some_salt'
            n = 16384
            r = 8
            p = 1
            #Flagga för att markera om en match hittas
            match_found = False

            #For loop för att börja jämföra lösenord med hashes
            for line in file:
                hashed = line.strip()
            #Error hantering
            try:
                #Öppnar fil med lösenord för att jämföra mot hashes
                with open(wordlist, 'r') as passwords:
                    for line in passwords:
                        word = line.strip()
                        try:
                            if algorithm == "md5":
                                hashed_word = hashlib.md5(word.encode()).hexdigest()
                            elif algorithm == "sha256":
                                hashed_word = hashlib.sha256(word.encode()).hexdigest()
                            elif algorithm == "bcrypt":
                                    #Bcrypt har ett annat sätt att jämföra hashes än vad de andra hashes har i denna kod
                                    if bcrypt.checkpw(word.encode(), hashed.encode()):
                                        print(f"Lösenord {word} matchar med hashen {hashed}")
                                        #Flagga för att markera om en match hittas
                                        match_found = True
                                    continue
                            elif algorithm == "scrypt":
                                hashed_word = hashlib.scrypt(word.encode(), salt=salt, n=n, r=r, p=p).hex()

                            #Kontrollera om lösenordens hash matchar någon av våra hashes
                            if hashed_word == hashed:
                                print(f"Lösenord {word} matchar med hashen {hashed}")
                                #Flagga för att markera om en match hittas
                                match_found = True
                                continue

    #Olika error meddelanden nedanför
                        except Exception as e:
                            print(f"Fel vid bearbetning av lösenord '{word}':", e)
            
            except FileNotFoundError:
                print(f"Ordlistfilen '{wordlist}' hittades inte.")
            except IOError:
                print(f"Kunde inte läsa ordlistfilen '{wordlist}'.")
            except Exception as e:
                print("Ett oväntat fel inträffade vid bearbetning av hashen:", e)

        #Ifall flaggan fortfarande inte är True så skickas ett meddelande att det inte fanns någon match
        if not match_found:
            print("Inga matchande lösenord hittades för någon av hasharna.")

        return None      
    except FileNotFoundError:
        print(f"Hashfilen '{hash_file}' hittades inte.")
    except IOError:
        print(f"Kunde inte läsa hashfilen '{hash_file}'.")
    except Exception as e:
        print("Ett oväntat fel inträffade vid uppläsning av hashfilen:", e)
    return None

                   
#Kontrollerar ifall användaren vill använda en fil av hatches eller bara en specifik hash
if args.mode == "scan_a_hash":
    #if not args.hash:
          #  parser.error("Du behöver ange vilken hash du vill försöka knäcka efter --hash.")
    crack_password(args.hash, args.wordlist, args.algorithm)
elif args.mode == "scan_file":
    #if not args.file:
          #  parser.error("Du behöver ange vilken hash-fil du vill försöka knäcka efter --file.")
    crack_all_hashes_in_file(args.file, args.wordlist, args.algorithm)