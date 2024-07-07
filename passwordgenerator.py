import tkinter as tk
from tkinter import messagebox, ttk
import random
import string
import subprocess
import sys
from tkinter.scrolledtext import ScrolledText

try:
    import pyperclip
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyperclip"])
    import pyperclip

SPECIAL_CHARS = "!#$%&@€₺"

def generate_password(length, use_uppercase, use_lowercase, use_numbers, use_special, allow_repeats):
    char_sets = ''.join([
        string.ascii_uppercase * use_uppercase,
        string.ascii_lowercase * use_lowercase,
        string.digits * use_numbers,
        SPECIAL_CHARS * use_special
    ])
    
    if not char_sets:
        raise ValueError("At least one character type must be selected")
    
    if not allow_repeats and length > len(char_sets):
        raise ValueError("Length exceeds the number of unique characters available")
    
    return ''.join(random.choices(char_sets, k=length) if allow_repeats else random.sample(char_sets, length))

def evaluate_password_strength(password):
    length = len(password)
    categories = sum([
        any(c.isupper() for c in password),
        any(c.islower() for c in password),
        any(c.isdigit() for c in password),
        any(c in SPECIAL_CHARS for c in password)
    ])
    
    score = length + categories * 2
    
    strength_levels = [
        (24, "Very Strong", "green"),
        (18, "Strong", "blue"),
        (12, "Medium", "orange"),
        (6, "Weak", "red"),
        (0, "Very Weak", "dark red")
    ]
    
    return next((strength, color) for threshold, strength, color in strength_levels if score >= threshold)

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")
        self.root.geometry("400x550")
        self.root.resizable(True, True)
        self.password_history = []
        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.create_length_input(main_frame)
        self.create_options(main_frame)
        self.create_buttons(main_frame)
        self.create_result_labels(main_frame)
        self.create_history_section(main_frame)

    def create_length_input(self, parent):
        input_frame = ttk.Frame(parent)
        input_frame.pack(pady=5)

        ttk.Label(input_frame, text="Password Length:").pack(side=tk.LEFT, padx=10)
        self.length_var = tk.IntVar(value=12)
        ttk.Scale(input_frame, from_=1, to_=100, orient=tk.HORIZONTAL, variable=self.length_var, command=self.update_length_label).pack(side=tk.LEFT, padx=10)
        self.length_label = ttk.Label(input_frame, text="12")
        self.length_label.pack(side=tk.LEFT)

    def create_options(self, parent):
        options_frame = ttk.Frame(parent)
        options_frame.pack(pady=5)

        self.option_vars = {
            "Uppercase": tk.BooleanVar(value=True),
            "Lowercase": tk.BooleanVar(value=True),
            "Numbers": tk.BooleanVar(value=True),
            "Special": tk.BooleanVar(value=True),
            "Repeats": tk.BooleanVar(value=True)
        }

        for text, var in self.option_vars.items():
            ttk.Checkbutton(options_frame, text=f"Include {text}", variable=var).pack(anchor='w', padx=10, pady=2)

    def create_buttons(self, parent):
        button_frame = ttk.Frame(parent)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Generate Password", command=self.generate_password).pack(side=tk.LEFT, padx=5)
        self.copy_button = ttk.Button(button_frame, text="Copy to Clipboard", command=self.copy_to_clipboard, state=tk.DISABLED)
        self.copy_button.pack(side=tk.LEFT, padx=5)

    def create_result_labels(self, parent):
        self.result_label = ttk.Label(parent, text="", foreground="green", wraplength=380, justify="center")
        self.result_label.pack(pady=5)
        self.strength_label = ttk.Label(parent, text="", wraplength=380, justify="center")
        self.strength_label.pack(pady=5)

    def create_history_section(self, parent):
        ttk.Label(parent, text="Password History:", wraplength=380, justify="center").pack(pady=5)

        self.history_text = ScrolledText(parent, height=5, state=tk.DISABLED)
        self.history_text.pack(fill=tk.BOTH, pady=5, expand=True)

        ttk.Button(parent, text="Clear History", command=self.clear_history).pack(pady=5)

    def update_length_label(self, *args):
        self.length_label.config(text=str(int(float(self.length_var.get()))))

    def generate_password(self):
        try:
            length = int(self.length_var.get())
            self.generated_password = generate_password(
                length,
                self.option_vars["Uppercase"].get(),
                self.option_vars["Lowercase"].get(),
                self.option_vars["Numbers"].get(),
                self.option_vars["Special"].get(),
                self.option_vars["Repeats"].get()
            )
            self.result_label.config(text=f"Generated password: {self.generated_password}")
            self.copy_button.config(state=tk.NORMAL)

            strength, color = evaluate_password_strength(self.generated_password)
            self.strength_label.config(text=f"Password Strength: {strength}", foreground=color)

            self.password_history.append(self.generated_password)
            self.update_history()
        except ValueError as ve:
            messagebox.showerror("Error", str(ve))
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def copy_to_clipboard(self):
        pyperclip.copy(self.generated_password)
        messagebox.showinfo("Success", "Password copied to clipboard")

    def update_history(self):
        self.history_text.config(state=tk.NORMAL)
        self.history_text.delete('1.0', tk.END)
        for password in self.password_history[-5:]:
            self.history_text.insert(tk.END, f"{password}\n")
        self.history_text.config(state=tk.DISABLED)
        self.history_text.see(tk.END)

    def clear_history(self):
        self.password_history.clear()
        self.update_history()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
