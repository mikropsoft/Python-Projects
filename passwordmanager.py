import os
import json
import hashlib
import subprocess
import sys
import random
import string
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext, filedialog

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "password_data")
os.makedirs(DATA_DIR, exist_ok=True)

DATA_FILE = os.path.join(DATA_DIR, 'passwords.json')
KEY_FILE = os.path.join(DATA_DIR, 'key.key')

def generate_key(master_password):
    return hashlib.sha256(master_password.encode()).digest()

def load_key(master_password):
    key = generate_key(master_password)
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as key_file:
            stored_key = key_file.read()
            if key == stored_key:
                return key
            raise ValueError("Incorrect master password!")
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    return key

def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(decrypted_padded_data) + unpadder.finalize()

def load_data(key):
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'rb') as file:
                encrypted_data = file.read()
                decrypted_data = decrypt_data(encrypted_data, key)
                return json.loads(decrypted_data)
        except Exception as e:
            messagebox.showerror("Error", f"Error decrypting data: {e}")
    return {}

def save_data(data, key):
    try:
        encrypted_data = encrypt_data(json.dumps(data).encode(), key)
        with open(DATA_FILE, 'wb') as file:
            file.write(encrypted_data)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save data: {e}")

def generate_password(length=16, use_special_chars=True):
    chars = string.ascii_letters + string.digits + (string.punctuation if use_special_chars else "")
    return ''.join(random.choice(chars) for _ in range(length))

def center_window(window):
    window.update_idletasks()
    width = window.winfo_width()
    height = window.winfo_height()
    x = (window.winfo_screenwidth() // 2) - (width // 2)
    y = (window.winfo_screenheight() // 2) - (height // 2)
    window.geometry(f'{width}x{height}+{x}+{y}')

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.withdraw()
        self.root.title("Password Manager Lite")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.master_password = self.get_master_password()
        if not self.master_password:
            self.root.destroy()
            return

        try:
            self.key = load_key(self.master_password)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            self.root.destroy()
            return

        self.data = load_data(self.key)
        
        self.root.deiconify()
        self.create_widgets()
        center_window(self.root)

    def get_master_password(self):
        password = simpledialog.askstring("Master Password", "Enter master password:", show='*')
        if not password:
            return None
        return password

    def create_widgets(self):
        self.text_area = scrolledtext.ScrolledText(self.root, width=60, height=20, state=tk.DISABLED)
        self.text_area.grid(row=0, column=0, columnspan=3, padx=10, pady=10)

        button_frame = tk.Frame(self.root)
        button_frame.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

        buttons = [
            ("Add Password", self.show_add_password_window),
            ("View Password", self.show_view_password_window),
            ("Update Password", self.show_update_password_window),
            ("Delete Password", self.show_delete_password_window),
            ("List All Passwords", self.toggle_list_passwords),
            ("Search Password", self.search_password),
            ("Change Master Password", self.change_master_password),
            ("Export Passwords", self.export_passwords),
            ("Import Passwords", self.import_passwords)
        ]

        self.buttons = {}
        for i, (text, command) in enumerate(buttons):
            btn = tk.Button(button_frame, text=text, command=command, width=20, height=2)
            btn.grid(row=i//3, column=i%3, padx=5, pady=5)
            self.buttons[text] = btn

    def show_add_password_window(self):
        self.manage_password_window("Add Password", self.add_password)

    def show_view_password_window(self):
        self.manage_password_window("View Password", self.view_password, is_view=True)

    def show_update_password_window(self):
        self.manage_password_window("Update Password", self.update_password)

    def show_delete_password_window(self):
        self.manage_password_window("Delete Password", self.delete_password, is_delete=True)

    def manage_password_window(self, title, action, is_view=False, is_delete=False):
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("400x250")
        center_window(window)

        entries = {}
        for i, field in enumerate(["Site", "Username", "Password"]):
            tk.Label(window, text=f"{field}:").grid(row=i, column=0, padx=10, pady=10, sticky="e")
            entry = tk.Entry(window, width=30)
            entry.grid(row=i, column=1, padx=10, pady=10)
            entries[field.lower()] = entry

        if is_view or is_delete:
            entries["username"].config(state=tk.DISABLED)
            entries["password"].config(state=tk.DISABLED)

        button_frame = tk.Frame(window)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)

        if not is_view and not is_delete:
            tk.Button(button_frame, text="Generate Password", command=lambda: entries["password"].insert(0, generate_password()), width=15).pack(side=tk.LEFT, padx=5)

        def on_submit():
            site = entries["site"].get()
            username = entries["username"].get()
            password = entries["password"].get()
            if action:
                action(site, username, password, window)

        tk.Button(button_frame, text="Submit", command=on_submit, width=15).pack(side=tk.LEFT, padx=5)

        if is_view:
            tk.Button(button_frame, text="Copy Username", command=lambda: self.copy_to_clipboard(entries["username"].get()), width=15).pack(side=tk.LEFT, padx=5)
            tk.Button(button_frame, text="Copy Password", command=lambda: self.copy_to_clipboard(entries["password"].get()), width=15).pack(side=tk.LEFT, padx=5)

    def add_password(self, site, username, password, window):
        if site and username and password:
            self.data[site] = {"username": username, "password": password}
            save_data(self.data, self.key)
            messagebox.showinfo("Success", f"Password for {site} saved.")
            window.destroy()
        else:
            messagebox.showwarning("Error", "All fields are required.")

    def view_password(self, site, username, password, window):
        if site in self.data:
            info = self.data[site]
            username_entry = window.children["!entry2"]
            password_entry = window.children["!entry3"]
            username_entry.config(state=tk.NORMAL)
            password_entry.config(state=tk.NORMAL)
            username_entry.delete(0, tk.END)
            username_entry.insert(0, info["username"])
            password_entry.delete(0, tk.END)
            password_entry.insert(0, info["password"])
            username_entry.config(state=tk.DISABLED)
            password_entry.config(state=tk.DISABLED)
        else:
            messagebox.showwarning("Not Found", "No password found for this site.")

    def update_password(self, site, username, password, window):
        if site in self.data and username and password:
            self.data[site] = {"username": username, "password": password}
            save_data(self.data, self.key)
            messagebox.showinfo("Success", f"Password for {site} updated.")
            window.destroy()
        else:
            messagebox.showwarning("Error", "Please ensure all fields are filled out correctly.")

    def delete_password(self, site, username, password, window):
        if site in self.data:
            confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the password for {site}?")
            if confirm:
                del self.data[site]
                save_data(self.data, self.key)
                messagebox.showinfo("Success", f"Password for {site} deleted.")
                window.destroy()
        else:
            messagebox.showwarning("Not Found", "No password found for this site.")

    def toggle_list_passwords(self):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete('1.0', tk.END)
        if self.buttons["List All Passwords"].cget('text') == "Hide Passwords":
            self.buttons["List All Passwords"].config(text="List All Passwords")
        else:
            if self.data:
                for site, info in self.data.items():
                    self.text_area.insert(tk.END, f"Site: {site}\nUsername: {info['username']}\nPassword: {info['password']}\n\n")
            else:
                self.text_area.insert(tk.END, "No passwords stored.")
            self.buttons["List All Passwords"].config(text="Hide Passwords")
        self.text_area.config(state=tk.DISABLED)

    def search_password(self):
        search_term = simpledialog.askstring("Search Password", "Enter site to search for:")
        if search_term:
            self.text_area.config(state=tk.NORMAL)
            self.text_area.delete('1.0', tk.END)
            results = [site for site in self.data if search_term.lower() in site.lower()]
            if results:
                for site in results:
                    info = self.data[site]
                    self.text_area.insert(tk.END, f"Site: {site}\nUsername: {info['username']}\nPassword: {info['password']}\n\n")
            else:
                self.text_area.insert(tk.END, "No password found for this site.")
            self.text_area.config(state=tk.DISABLED)

    def change_master_password(self):
        old_password = simpledialog.askstring("Old Master Password", "Enter current master password:", show='*')
        if old_password and generate_key(old_password) == self.key:
            new_password = self.get_master_password()
            if new_password:
                new_key = generate_key(new_password)
                save_data(self.data, new_key)
                self.key = new_key
                self.master_password = new_password
                with open(KEY_FILE, 'wb') as key_file:
                    key_file.write(new_key)
                messagebox.showinfo("Success", "Master password changed successfully.")
        else:
            messagebox.showerror("Error", "Incorrect current master password.")

    def export_passwords(self):
        export_file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if export_file:
            try:
                with open(export_file, 'w') as f:
                    json.dump(self.data, f, indent=4)
                messagebox.showinfo("Success", f"Passwords exported to {export_file}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export passwords: {e}")

    def import_passwords(self):
        import_file = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if import_file:
            try:
                with open(import_file, 'r') as f:
                    imported_data = json.load(f)
                self.data.update(imported_data)
                save_data(self.data, self.key)
                messagebox.showinfo("Success", f"Passwords imported from {import_file}")
                self.toggle_list_passwords()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import passwords: {e}")

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        messagebox.showinfo("Copied", "Text copied to clipboard.")

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
