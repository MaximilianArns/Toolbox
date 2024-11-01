Verktyget ska innehålla en README-fil med instruktioner om hur verktyget används, exempelkörningar och kända begränsningar.
# Verktygslåda
## Introduktion
Detta projekt är en verktygslåda med en samling projekt och verktyg designade för att vara relevant för it-säkerhet. Verktygen är, generera en nyckel för att kryptera och dekryptera, möjligheten för att kryptera och dekryptera, hasha lösenord, knäcka hashade lösenord, skanna ip adresser med hjälp av Nmap.

## Verktyg 1 (generate_key)
För att generera en nyckel så kan man köra denna kommandorad:  
python main_toolbox.py --tool generate_key secret

## Verktyg 2 (crypto_tool)
För att kryptera text med den skapna nyckeln så kan man köra denna kommandorad:   
python main_toolbox.py --tool crypto --mode kryptera --message "Hemlig text" secret.key hemlig.txt  

För att dekryptera en text med den skapna nyckeln så kan man köra följande kommandorad:  
python main_toolbox.py --tool crypto --mode dekryptera secret.key hemlig.txt

## Verktyg 3 (hash_password)
För att hasha ett lösenord så kan man köra denna kommando:  
python main_toolbox.py --tool hash_password --password password1234 --algorithm bcrypt

## Verktyg 4 (crack_hashes)
För att knäcka hashes med exempelvis bcrypt algoritm så kan man använda denna kommandorad:  
python main_toolbox.py --tool crack_hashes --mode scan_a_hash --hash "skriv in hashen här" passwords.txt bcrypt

## Verktyg 5 (nmap)
För att använda skanna tcp portar med hjälp av nmap så kan man skriva en sånhär kommandorad:  
python main_toolbox.py --tool nmap --mode single_ip --scan_type syn --ip_addr "skriv ip adressen du vill skanna här"


## Kända begränsningar
Nmap:
Firewall och IDS: Nmap-skanningar kan blockeras av brandväggar och intrångsdetekteringssystem, vilket påverkar resultaten.
Timing och hastighet: Snabba skanningar kan leda till paketförlust, medan långsamma skanningar tar längre tid och kan vara ineffektiva.
Root-rättigheter: Vissa funktioner kräver administratörsrättigheter, vilket kan begränsa användningen.

Hashing:
Kollisionsrisk: Vissa hashing-algoritmer (t.ex. MD5, SHA-1) har kända kollisionsproblem, vilket kan kompromettera säkerheten.
Hash-längd: Kortare hash-längder är mer utsatta för brute-force-attacker.

Kryptering:
Nyckelhantering: Säkerhet beror på hur nycklar hanteras; dålig nyckelhantering kan leda till allvarliga sårbarheter.
 
