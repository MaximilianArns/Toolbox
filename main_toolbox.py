import subprocess
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Toolbox för IT-säkerhetsverktyg")
    parser.add_argument("--tool", choices=["crypto", "generate_key", "crack_hashes", "hash_password", "nmap"], help="Välj verktyg att köra")

    args, args_extra = parser.parse_known_args()

    if args.tool == "crypto":
        subprocess.run(["python", "crypto_tool.py"] + args_extra)
    elif args.tool == "generate_key":
        subprocess.run(["python", "generate_key.py"] + args_extra)
    elif args.tool == "crack_hashes":
        subprocess.run(["python", "crack_hashes.py"] + args_extra)
    elif args.tool == "hash_password":
        subprocess.run(["python", "hash_password.py"] + args_extra)
    elif args.tool == "nmap":
        subprocess.run(["python", "nmaplab.py"] + args_extra)
    else:
        print("Inget giltigt verktyg valdes, vänligen välj bland dessa alternativ crypto, generate_key, crack_hashes, hash_password, nmap.")