import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import re
import string
from collections import Counter

class TextAnalyzer:
    def __init__(self, master):
        self.master = master
        master.title("PyTextAnalyzer")
        self.center_window(600, 700)

        self.create_widgets()
        self.bind_events()

    def center_window(self, width, height):
        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        self.master.geometry(f"{width}x{height}+{x}+{y}")

    def create_widgets(self):
        self.frame = ttk.Frame(self.master, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)

        self.frame.columnconfigure(0, weight=1)
        self.frame.columnconfigure(1, weight=1)

        self.input_label = ttk.Label(self.frame, text="Enter Text:")
        self.input_label.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=5)

        self.input_text = tk.Text(self.frame, height=10, wrap=tk.WORD)
        self.input_text.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.button_frame = ttk.Frame(self.frame)
        self.button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        self.button_frame.columnconfigure(0, weight=1)
        self.button_frame.columnconfigure(1, weight=1)
        self.button_frame.columnconfigure(2, weight=1)
        self.button_frame.columnconfigure(3, weight=1)

        self.analyze_button = ttk.Button(self.button_frame, text="Analyze", command=self.analyze_text)
        self.analyze_button.grid(row=0, column=0, padx=5, sticky=(tk.W, tk.E))

        self.clear_button = ttk.Button(self.button_frame, text="Clear", command=self.clear_text)
        self.clear_button.grid(row=0, column=1, padx=5, sticky=(tk.W, tk.E))

        self.copy_button = ttk.Button(self.button_frame, text="Copy Results", command=self.copy_results)
        self.copy_button.grid(row=0, column=2, padx=5, sticky=(tk.W, tk.E))

        self.load_button = ttk.Button(self.button_frame, text="Load File", command=self.load_file)
        self.load_button.grid(row=0, column=3, padx=5, sticky=(tk.W, tk.E))

        self.result_label = ttk.Label(self.frame, text="Results:")
        self.result_label.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)

        self.result_text = tk.Text(self.frame, height=15, state="normal")
        self.result_text.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        for child in self.frame.winfo_children():
            child.grid_configure(padx=5, pady=5)

    def bind_events(self):
        self.master.bind('<Control-a>', lambda e: self.analyze_text())
        self.master.bind('<Control-c>', lambda e: self.copy_results())
        self.master.bind('<Control-l>', lambda e: self.load_file())

    def analyze_text(self):
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

    def perform_analysis(self, text):
        word_list = text.split()
        char_list = list(text.lower())
        
        vowels = 'aeiou'
        consonants = string.ascii_lowercase.replace('aeiou', '')

        analysis = {
            "Vowels": sum(1 for char in char_list if char in vowels),
            "Consonants": sum(1 for char in char_list if char in consonants),
            "Numbers": sum(1 for char in char_list if char.isdigit()),
            "Special Characters": sum(1 for char in char_list if char in string.punctuation),
            "Words": len(word_list),
            "Sentences": len(re.findall(r'\w+[.!?]', text)) or 1,
            "Paragraphs": text.count('\n') + 1,
            "Most Common Word": Counter(word_list).most_common(1)[0][0] if word_list else 'N/A',
            "Most Common Character": Counter(char for char in char_list if char.isalnum()).most_common(1)[0][0] if char_list else 'N/A',
            "Average Word Length": sum(len(word) for word in word_list) / len(word_list) if word_list else 0,
            "Longest Word": max(word_list, key=len) if word_list else 'N/A',
        }
        return analysis

    def display_results(self, analysis):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        for key, value in analysis.items():
            self.result_text.insert(tk.END, f"{key}: {value:.2f}\n" if isinstance(value, float) else f"{key}: {value}\n")
        self.result_text.config(state="disabled")

    def clear_text(self):
        self.input_text.delete("1.0", tk.END)
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")
        self.status_var.set("All text cleared.")

    def copy_results(self):
        results = self.result_text.get("1.0", tk.END).strip()
        if results:
            self.master.clipboard_clear()
            self.master.clipboard_append(results)
            self.status_var.set("Results copied to clipboard.")
        else:
            messagebox.showinfo("Info", "No results to copy.")

    def load_file(self):
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
