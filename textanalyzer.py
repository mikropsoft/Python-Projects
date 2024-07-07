import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import re
import string
from collections import Counter
from typing import Dict, Any

class TextAnalyzer:
    def __init__(self, master: tk.Tk):
        self.master = master
        master.title("PyTextAnalyzer")
        self.center_window(600, 700)
        self.create_widgets()
        self.bind_events()

    def center_window(self, width: int, height: int) -> None:
        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.master.geometry(f"{width}x{height}+{x}+{y}")

    def create_widgets(self) -> None:
        self.frame = ttk.Frame(self.master, padding="10")
        self.frame.grid(row=0, column=0, sticky="nsew")
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)

        self.frame.columnconfigure((0, 1), weight=1)
        self.frame.rowconfigure(4, weight=1)

        ttk.Label(self.frame, text="Enter Text:").grid(row=0, column=0, columnspan=2, sticky="w", pady=5)

        self.input_text = tk.Text(self.frame, height=10, wrap=tk.WORD)
        self.input_text.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=5)

        button_frame = ttk.Frame(self.frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        button_frame.columnconfigure((0, 1, 2, 3), weight=1)

        buttons = [
            ("Analyze", self.analyze_text),
            ("Clear", self.clear_text),
            ("Copy Results", self.copy_results),
            ("Load File", self.load_file)
        ]

        for i, (text, command) in enumerate(buttons):
            ttk.Button(button_frame, text=text, command=command).grid(row=0, column=i, padx=5, sticky="ew")

        ttk.Label(self.frame, text="Results:").grid(row=3, column=0, columnspan=2, sticky="w", pady=5)

        self.result_text = tk.Text(self.frame, height=15, state="disabled")
        self.result_text.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=5)

        self.status_var = tk.StringVar()
        ttk.Label(self.frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).grid(row=5, column=0, columnspan=2, sticky="ew", pady=5)

        for child in self.frame.winfo_children():
            child.grid_configure(padx=5, pady=5)

    def bind_events(self) -> None:
        self.master.bind('<Control-a>', lambda e: self.analyze_text())
        self.master.bind('<Control-c>', lambda e: self.copy_results())
        self.master.bind('<Control-l>', lambda e: self.load_file())

    def analyze_text(self) -> None:
        text = self.input_text.get("1.0", "end-1c").strip()
        if not text:
            messagebox.showwarning("Warning", "Please enter some text to analyze.")
            return

        try:
            analysis = self.perform_analysis(text)
            self.display_results(analysis)
            self.status_var.set("Analysis completed successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during analysis: {str(e)}")
            self.status_var.set("Analysis failed.")

    def perform_analysis(self, text: str) -> Dict[str, Any]:
        word_list = text.split()
        char_list = text.lower()
        
        vowels = set('aeiou')
        consonants = set(string.ascii_lowercase) - vowels

        analysis = {
            "Vowels": sum(char in vowels for char in char_list),
            "Consonants": sum(char in consonants for char in char_list),
            "Numbers": sum(char.isdigit() for char in char_list),
            "Special Characters": sum(char in string.punctuation for char in char_list),
            "Words": len(word_list),
            "Sentences": len(re.findall(r'\w+[.!?]', text)) or 1,
            "Paragraphs": text.count('\n') + 1,
            "Most Common Word": Counter(word_list).most_common(1)[0][0] if word_list else 'N/A',
            "Most Common Character": Counter(char for char in char_list if char.isalnum()).most_common(1)[0][0] if char_list else 'N/A',
            "Average Word Length": sum(len(word) for word in word_list) / len(word_list) if word_list else 0,
            "Longest Word": max(word_list, key=len) if word_list else 'N/A',
        }
        return analysis

    def display_results(self, analysis: Dict[str, Any]) -> None:
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        for key, value in analysis.items():
            self.result_text.insert(tk.END, f"{key}: {value:.2f}\n" if isinstance(value, float) else f"{key}: {value}\n")
        self.result_text.config(state="disabled")

    def clear_text(self) -> None:
        self.input_text.delete("1.0", tk.END)
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")
        self.status_var.set("All text cleared.")

    def copy_results(self) -> None:
        results = self.result_text.get("1.0", tk.END).strip()
        if results:
            self.master.clipboard_clear()
            self.master.clipboard_append(results)
            self.status_var.set("Results copied to clipboard.")
        else:
            messagebox.showinfo("Info", "No results to copy.")

    def load_file(self) -> None:
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                self.input_text.delete("1.0", tk.END)
                self.input_text.insert(tk.END, content)
                self.status_var.set(f"File loaded: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
                self.status_var.set("File loading failed.")

if __name__ == "__main__":
    root = tk.Tk()
    app = TextAnalyzer(root)
    root.mainloop()
