Verktyget ska innehålla en README-fil med instruktioner om hur verktyget används, exempelkörningar och kända begränsningar.
# Toolbox
## Introduction
This project is a toolbox containing a collection of projects and tools designed to be relevant for cybersecurity. The tools include generating a key for encryption and decryption, encrypting and decrypting data, hashing passwords, cracking hashed passwords, and scanning IP addresses using Nmap.

## Tool 1 (generate_key)
To generate a key, run the following command: 
python main_toolbox.py --tool generate_key secret

## Tool 2 (crypto_tool)
To encrypt text using the generated key, run the following command:   
python main_toolbox.py --tool crypto --mode encrypt --message "Secret text" secret.key secret.txt 

To decrypt text using the generated key, run the following command:  
python main_toolbox.py --tool crypto --mode decrypt secret.key secret.txt

## Tool 3 (hash_password)
To hash a password, run the following command:  
python main_toolbox.py --tool hash_password --password password1234 --algorithm bcrypt

## Tool 4 (crack_hashes)
To crack hashes using, for example, the bcrypt algorithm, run the following command:  
python main_toolbox.py --tool crack_hashes --mode scan_a_hash --hash "insert hash here" passwords.txt bcrypt

Tool 5 (nmap)
To scan TCP ports using Nmap, run the following command: 
python main_toolbox.py --tool nmap --mode single_ip --scan_type syn --ip_addr "insert the IP address you want to scan here"


## Known Limitations
Nmap:
- Firewalls and IDS: Nmap scans can be blocked by firewalls and intrusion detection systems, affecting the results.
- Timing and speed: Fast scans may result in packet loss, while slow scans take longer and may be inefficient.
- Root privileges: Some functions require administrative privileges, which can limit usability.

Hashing:
- Collision risk: Some hashing algorithms (e.g., MD5, SHA-1) have known collision vulnerabilities, which can compromise security.
- Hash length: Shorter hash lengths are more susceptible to brute-force attacks.

Kryptering:
- Key management: Security depends on how keys are managed; poor key management can lead to severe vulnerabilities.
