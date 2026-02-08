import time
import threading
import atexit
from getpass import getpass
import pyperclip

from vault_class import Vault

AUTO_LOCK_SECONDS = 120
CLIPBOARD_CLEAR_SECONDS = 15


# ───────── Clipboard hygiene ─────────

def clear_clipboard_now():
    try:
        pyperclip.copy("")
    except Exception:
        pass


def clear_clipboard_after(delay):
    def _clear():
        time.sleep(delay)
        clear_clipboard_now()
    threading.Thread(target=_clear, daemon=True).start()


atexit.register(clear_clipboard_now)


def entropy_info(vault, pwd):
    charset = 0
    if any(c.islower() for c in pwd): charset += 26
    if any(c.isupper() for c in pwd): charset += 26
    if any(c.isdigit() for c in pwd): charset += 10
    if any(not c.isalnum() for c in pwd): charset += 32

    entropy = vault.calculate_entropy(charset, len(pwd))

    if entropy < 40: level = "WEAK"
    elif entropy < 60: level = "OKAY"
    elif entropy < 80: level = "STRONG"
    else: level = "EXCELLENT"

    print(f"Entropy: {entropy} bits → {level}")
    return entropy


vault = Vault()

try:
    vault.unlock_or_create(getpass("Enter master password: "))
except ValueError:
    print("Wrong master password.")
    exit(1)

print("Vault unlocked.")
last_activity = time.time()

try:
    while True:
        if time.time() - last_activity > AUTO_LOCK_SECONDS:
            print("Vault locked due to inactivity.")
            break

        print("\n1. Add entry")
        print("2. Get entry")
        print("3. Search sites")
        print("4. Generate password")
        print("5. Delete entry")
        print("6. Edit entry")
        print("7. List sites")
        print("8. Exit")

        choice = input("> ").strip()
        last_activity = time.time()

        if choice == "1":
            site = input("Site: ")
            user = input("Username: ")
            pwd = getpass("Password: ")
            if entropy_info(vault, pwd) < 40:
                if input("Save anyway? (y/N): ").lower() != "y":
                    continue
            vault.add_entry(site, user, pwd)
            print("Saved.")

        elif choice == "2":
            site = input("Site: ")
            entries = vault.get_entries_by_site(site)
            for i, (_, u, _) in enumerate(entries):
                print(f"{i+1}. {u}")
            idx = input("Select: ")
            pyperclip.copy(entries[int(idx)-1][2])
            clear_clipboard_after(CLIPBOARD_CLEAR_SECONDS)
            print("Copied.")

        elif choice == "3":
            q = input("Search: ")
            sites = vault.search_sites(q)
            for i, s in enumerate(sites):
                print(f"{i+1}. {s}")
            sel = input("Select site: ")
            entries = vault.get_entries_by_site(sites[int(sel)-1])
            for i, (_, u, _) in enumerate(entries):
                print(f"{i+1}. {u}")
            acc = input("Select account: ")
            action = input("[c] copy  [d] delete: ").lower()
            if action == "c":
                pyperclip.copy(entries[int(acc)-1][2])
                clear_clipboard_after(CLIPBOARD_CLEAR_SECONDS)
            elif action == "d":
                vault.delete_entry(entries[int(acc)-1][0])
                print("Deleted.")

        elif choice == "4":
            pwd, ent = vault.generate_password()
            pyperclip.copy(pwd)
            clear_clipboard_after(CLIPBOARD_CLEAR_SECONDS)
            print(f"Generated (entropy {ent} bits)")

        elif choice == "5":
            site = input("Site: ")
            entries = vault.get_entries_by_site(site)
            for i, (_, u, _) in enumerate(entries):
                print(f"{i+1}. {u}")
            idx = input("Select: ")
            vault.delete_entry(entries[int(idx)-1][0])
            print("Deleted.")

        elif choice == "6":
            site = input("Site: ")
            entries = vault.get_entries_by_site(site)
            for i, (_, u, _) in enumerate(entries):
                print(f"{i+1}. {u}")
            idx = input("Select: ")
            eid, old_user, _ = entries[int(idx)-1]

            new_user = input(f"New username (ENTER keep '{old_user}'): ").strip() or None
            new_pwd = None

            if input("Change password? (y/N): ").lower() == "y":
                pwd = getpass("New password: ")
                if entropy_info(vault, pwd) < 40:
                    if input("Save anyway? (y/N): ").lower() != "y":
                        continue
                new_pwd = pwd

            vault.edit_entry(eid, new_user, new_pwd)
            print("Updated.")

        elif choice == "7":
            for s in vault.list_sites():
                print("-", s)

        elif choice == "8":
            break

        else:
            print("Invalid option.")

finally:
    vault.lock()
    print("Vault locked.")
