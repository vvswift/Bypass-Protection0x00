import zipfile
import time
import sys


def log():
    time.sleep(1)
    print("""
\033[7;32m===========================
\033[7;33m=========ZIP Killer========
\033[7;31m===========================
\033[0m    """)


def trace(passwd_file, zip_file):
    try:
        start = time.time()
        with zipfile.ZipFile(zip_file, "r") as zf:
            with open(passwd_file, "r") as pf:
                for line in pf:
                    passwd = line.strip()
                    try:
                        zf.extractall(pwd=passwd.encode("utf-8"))
                        end = time.time()
                        print(
                            f"[+] Password Found: \033[1;33m{passwd} \033[0m{int(end - start)}s"
                        )
                        db = open("zip.conf", "w+")
                        db.write(f"{zip_file}:{passwd}\n")
                        db.close()
                        return True
                    except:
                        continue
        print("[!] Password Not Found in this wordlist.")
    except FileNotFoundError:
        print("[!] File not found:", zip_file, "or", passwd_file)
    except Exception as e:
        print("[!] Error:", e)


def show(file_name):
    try:
        with open("zip.conf", "r") as fx:
            for line in fx:
                is_name = line.strip()
                if is_name.startswith(file_name + ":"):
                    print("Found: \033[4;33m" + is_name + "\033[0m")
                    break
            else:
                print("Not found in zip.conf")
    except FileNotFoundError:
        print("[!] zip.conf file not found.")


def main():
    try:
        if "--help" in sys.argv:
            print("""
**Crack password password list using.** :-\n Usage: python zip_killer.py -zip [zipfile.zip] -pwd [passwdlist.txt]
**view Crack password.** :-\n Usage: python zip_killer -show [zipfile]
""")
        elif "-zip" in sys.argv and "-pwd" in sys.argv:
            log()
            zip_index = sys.argv.index("-zip") + 1
            pwd_index = sys.argv.index("-pwd") + 1

            zipfile_path = sys.argv[zip_index]
            passwdfile_path = sys.argv[pwd_index]

            trace(passwdfile_path, zipfile_path)
        elif "-show" in sys.argv:
            fnum = sys.argv.index("-show") + 1
            file_name = sys.argv[fnum]
            log()
            show(file_name)
        else:
            print("Invalid arguments. Use --help")
    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    main()
