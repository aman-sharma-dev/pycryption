
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import sys
import threading
from ttkthemes import ThemedTk
from app.crypto_utils import (
    encrypt_text, decrypt_text,
    encrypt_file, decrypt_file,
    encrypt_file_with_password, decrypt_file_with_password,
    derive_key_from_password,
    generate_key, load_key
)
import base64
import json # Import json for storing key and salt

# Placeholder for stream encryption/decryption functions that should ideally be in crypto_utils
# For now, these are simple read-all-then-process, which is not efficient for very large files.
# A proper implementation would use fixed-size chunks.
def _encrypt_stream(in_f, out_f, key):
    from cryptography.fernet import Fernet
    f = Fernet(key)
    chunk = in_f.read() # Reads the whole file, not stream-optimized
    encrypted_chunk = f.encrypt(chunk)
    out_f.write(encrypted_chunk)

def _decrypt_stream(in_f, out_f, key):
    from cryptography.fernet import Fernet
    f = Fernet(key)
    chunk = in_f.read() # Reads the whole file, not stream-optimized
    decrypted_chunk = f.decrypt(chunk)
    out_f.write(decrypted_chunk)

# Function to get absolute path to resource, works for dev and for PyInstaller
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = tk.Canvas(self, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)

        self.scrollable_frame_window = canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.bind(
            "<Configure>",
            lambda e: canvas.itemconfig(self.scrollable_frame_window, width=e.width)
        )

        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")


class EncryptorApp(ThemedTk):
    def __init__(self):
        super().__init__()
        self.set_theme("default")
        self.title("PyCryption") # Changed title
        
        # Use resource_path for the icon
        icon_path = resource_path("assets/favicon.ico")
        if os.path.exists(icon_path):
            self.iconbitmap(icon_path)
            print(f"Icon found and set: {icon_path}")
        else:
            print(f"Warning: Icon file not found at '{icon_path}'. Skipping icon setting.")

        self.geometry("600x550")
        self.resizable(False, False)

        # Path for the persistent key file
        self.key_file_path = os.path.join(os.path.expanduser("~"), ".PyCryption_key")
        self.active_key = None # Stores the currently active key (bytes)
        self.text_salt = b'a_fixed_salt_for_web_demo_' # Used for text encryption when no active_key

        theme_frame = ttk.Frame(self)
        theme_frame.pack(pady=5, padx=10, fill="x")
        ttk.Label(theme_frame, text="Theme:").pack(side="left")
        self.theme_selector = ttk.Combobox(theme_frame, values=self.get_themes(), height=10)
        self.theme_selector.set("default")
        self.theme_selector.pack(side="left", padx=5)
        self.theme_selector.bind("<<ComboboxSelected>>", self.change_theme)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, padx=10, expand=True, fill="both")

        self.text_tab = ScrollableFrame(self.notebook)
        self.file_tab = ScrollableFrame(self.notebook)
        self.manage_key_tab = ScrollableFrame(self.notebook)

        self.notebook.add(self.text_tab, text='Text Encryption')
        self.notebook.add(self.file_tab, text='File Encryption')
        self.notebook.add(self.manage_key_tab, text='Manage Key')

        self.create_text_widgets(self.text_tab.scrollable_frame)
        self.create_file_widgets(self.file_tab.scrollable_frame)
        self.create_manage_key_widgets(self.manage_key_tab.scrollable_frame)
        
        # Now that widgets are created, load the active key
        self.load_active_key_on_startup() # Attempt to load key on startup

        # Bind the closing protocol to save the key
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        self.save_active_key_on_exit()
        self.destroy()

    def load_active_key_on_startup(self):
        if os.path.exists(self.key_file_path):
            try:
                with open(self.key_file_path, "rb") as f:
                    # The key is stored as raw base64 bytes for Fernet
                    self.active_key = f.read()
                # Validate if it's a valid Fernet key length
                if not (len(self.active_key) == 44 and self.active_key.endswith(b'=')):
                     # Check for common base64 padding
                    print("Loaded key seems invalid (not standard Fernet length/padding), resetting.")
                    self.active_key = None
            except Exception as e:
                print(f"Error loading active key on startup: {e}")
                self.active_key = None # Ensure key is reset if loading fails
        self.update_key_display()


    def save_active_key_on_exit(self):
        if self.active_key:
            try:
                with open(self.key_file_path, "wb") as f:
                    f.write(self.active_key)
            except Exception as e:
                print(f"Error saving active key on exit: {e}")
        elif os.path.exists(self.key_file_path):
            # If no active key, but a file exists, delete it
            try:
                os.remove(self.key_file_path)
            except Exception as e:
                print(f"Error deleting old key file on exit: {e}")


    def change_theme(self, event):
        self.set_theme(self.theme_selector.get())

    def create_text_widgets(self, container):
        frame = ttk.Frame(container, padding="10")
        frame.pack(expand=True, fill="both")

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        ttk.Label(frame, text="Enter Text:").grid(row=0, column=0, columnspan=2, sticky="w", pady=2)
        self.text_input = tk.Text(frame, height=10, width=50)
        self.text_input.grid(row=1, column=0, columnspan=2, pady=5, sticky="ew")
        ttk.Label(frame, text="Password (if no active key):").grid(row=2, column=0, columnspan=2, sticky="w", pady=2)
        self.text_password_entry = ttk.Entry(frame, show="*")
        self.text_password_entry.grid(row=3, column=0, columnspan=2, pady=5, sticky="ew")

        ttk.Button(frame, text="Encrypt", command=self.encrypt_text_action).grid(row=4, column=0, pady=10, sticky="ew")
        ttk.Button(frame, text="Decrypt", command=self.decrypt_text_action).grid(row=4, column=1, pady=10, sticky="ew")
        ttk.Button(frame, text="Copy to Clipboard", command=self.copy_to_clipboard).grid(row=5, column=0, columnspan=2, pady=5, sticky="ew")
        
        ttk.Label(frame, text="Note: Uses active key from 'Manage Key' tab if available, else password.").grid(row=6, column=0, columnspan=2, sticky="w", pady=5)


    def create_file_widgets(self, container):
        frame = ttk.Frame(container, padding="10")
        frame.pack(expand=True, fill="both")

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(2, weight=1)
        frame.grid_columnconfigure(3, weight=0)

        ttk.Label(frame, text="Input File:").grid(row=0, column=0, columnspan=4, sticky="w", pady=2, padx=5)
        self.input_file_path = tk.StringVar()
        ttk.Entry(frame, textvariable=self.input_file_path, state="readonly").grid(row=1, column=0, columnspan=3, sticky="ew", pady=5, padx=5)
        ttk.Button(frame, text="Browse...", command=self.select_input_file).grid(row=1, column=3, sticky="e", padx=5)

        ttk.Label(frame, text="Password (if no active key):").grid(row=2, column=0, columnspan=4, sticky="w", pady=2, padx=5)
        self.file_password_entry = ttk.Entry(frame, show="*")
        self.file_password_entry.grid(row=3, column=0, columnspan=4, sticky="ew", pady=5, padx=5)

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=4, column=0, columnspan=4, pady=10)
        frame.grid_columnconfigure(0, weight=1)

        ttk.Button(button_frame, text="Encrypt File", command=self.encrypt_file_action).pack(side="left", expand=True, fill="x", padx=5)
        ttk.Button(button_frame, text="Decrypt File", command=self.decrypt_file_action).pack(side="left", expand=True, fill="x", padx=5)

        self.progress = ttk.Progressbar(frame, orient="horizontal", length=100, mode="determinate")
        self.progress.grid(row=5, column=0, columnspan=4, sticky="ew", pady=10, padx=5)
        
        ttk.Label(frame, text="Note: Uses active key from 'Manage Key' tab if available, else password.").grid(row=6, column=0, columnspan=4, sticky="w", pady=5)


    def create_manage_key_widgets(self, container):
        frame = ttk.Frame(container, padding="10")
        frame.pack(expand=True, fill="both")

        frame.grid_columnconfigure(0, weight=1)

        # --- Key Display/Input ---
        key_display_frame = ttk.LabelFrame(frame, text="Current Secret Key (Hex)", padding="10")
        key_display_frame.grid(row=0, column=0, sticky="ew", pady=10)
        key_display_frame.grid_columnconfigure(0, weight=1)

        self.key_display_text = tk.Text(key_display_frame, height=4, width=50, wrap=tk.WORD)
        self.key_display_text.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        self.key_display_text.bind("<KeyRelease>", self.update_active_key_from_display)


        # --- Key Actions ---
        key_actions_frame = ttk.Frame(frame)
        key_actions_frame.grid(row=1, column=0, sticky="ew", pady=10)
        key_actions_frame.grid_columnconfigure(0, weight=1)
        key_actions_frame.grid_columnconfigure(1, weight=1)

        ttk.Button(key_actions_frame, text="Generate New Key", command=self.generate_random_key_action).grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        ttk.Button(key_actions_frame, text="Load Key from File...", command=self.load_key_from_file_action).grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        ttk.Button(key_actions_frame, text="Copy to Clipboard", command=self.copy_active_key_to_clipboard).grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        ttk.Button(key_actions_frame, text="Save Key to File...", command=self.save_active_key_to_file).grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        self.update_key_display() # Initial display of key status

    def update_key_display(self):
        self.key_display_text.delete("1.0", tk.END)
        if self.active_key:
            try:
                # Attempt to decode base64 to raw bytes, then hex encode for display
                raw_key_bytes = base64.urlsafe_b64decode(self.active_key)
                self.key_display_text.insert("1.0", raw_key_bytes.hex())
                self.key_display_text.config(fg="green")
            except Exception:
                # Fallback if active_key is malformed base64
                self.key_display_text.insert("1.0", "Invalid active key format.")
                self.key_display_text.config(fg="red")
                self.active_key = None # Invalidate key if it's malformed
        else:
            self.key_display_text.insert("1.0", "No active key. Generate a new one or load from file.")
            self.key_display_text.config(fg="red")

    def update_active_key_from_display(self, event=None):
        key_hex = self.key_display_text.get("1.0", tk.END).strip()
        if not key_hex:
            self.active_key = None
            self.update_key_display()
            return
        try:
            # Attempt to decode hex to bytes
            potential_raw_key = bytes.fromhex(key_hex)
            # Fernet keys are base64 encoded, which is 44 bytes long, 
            # corresponding to 32 bytes (256 bits) of actual key data.
            # The hex representation of 32 bytes is 64 characters.
            if len(potential_raw_key) == 32: 
                self.active_key = base64.urlsafe_b64encode(potential_raw_key)
                self.key_display_text.config(fg="green") # Indicate valid key
            else:
                self.active_key = None
                self.key_display_text.config(fg="red")
                messagebox.showwarning("Invalid Key", "Key must be 32 bytes (64 hex characters).")

        except ValueError:
            # If fromhex fails, check if it's a direct base64 string
            try:
                potential_base64_key = key_hex.encode('utf-8')
                decoded_key = base64.urlsafe_b64decode(potential_base64_key)
                if len(decoded_key) == 32: # A valid Fernet key decodes to 32 bytes
                    self.active_key = potential_base64_key
                    self.key_display_text.config(fg="green")
                else:
                    raise ValueError("Incorrect length for base64 key.")
            except Exception: # Catch any base64 decoding errors or length mismatches
                self.active_key = None
                self.key_display_text.config(fg="red") # Indicate invalid key
            
        self.update_key_display() # Refresh display to show status


    def generate_random_key_action(self):
        self.active_key = generate_key() # Generate raw bytes (base64 encoded Fernet key)
        self.update_key_display()
        self.save_active_key_on_exit() # Save immediately after generation
        messagebox.showinfo("Key Generated", "A new random key has been generated and is now active.")

    def load_key_from_file_action(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("Key files", "*.key"), ("All files", "*.*")],
            title="Load Key File"
        )
        if filepath:
            try:
                loaded_key = load_key(filepath)
                if len(loaded_key) == 32: # If loaded as raw 32 bytes, encode to base64
                    self.active_key = base64.urlsafe_b64encode(loaded_key)
                elif len(loaded_key) == 44 and loaded_key.endswith(b'='): # Already base64 encoded Fernet key
                    self.active_key = loaded_key
                else:
                    raise ValueError("Key file content is not a valid 32-byte raw key or 44-byte base64 Fernet key.")

                self.update_key_display()
                self.save_active_key_on_exit() # Save immediately after loading
                messagebox.showinfo("Success", f"Key loaded from {filepath} and is now active.")
            except FileNotFoundError:
                messagebox.showerror("Error", "Selected key file not found.")
            except Exception as e:
                messagebox.showerror("Loading Failed", f"Could not load the key file: {e}")
            finally:
                if self.active_key is None: # If loading failed, ensure display is updated
                    self.update_key_display()
        else:
            # If user cancels file selection, active_key should not change, but display should be consistent
            self.update_key_display()

    def copy_active_key_to_clipboard(self):
        if self.active_key:
            try:
                # Ensure the key is in hex for clipboard for easier manual handling/viewing
                # Fernet keys are base64.urlsafe_b64encoded. To get raw bytes for hex, decode base64 first.
                raw_key_bytes = base64.urlsafe_b64decode(self.active_key)
                self.clipboard_clear()
                self.clipboard_append(raw_key_bytes.hex())
                messagebox.showinfo("Copied", "Active key (hex) copied to clipboard!")
            except Exception as e:
                messagebox.showerror("Error", f"Could not decode key for clipboard: {e}")
        else:
            messagebox.showwarning("No Key", "No active key to copy.")

    def save_active_key_to_file(self):
        if not self.active_key:
            messagebox.showerror("Error", "No active key to save. Generate or load one first.")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")],
            initialfile="secret.key",
            title="Save Active Key"
        )
        if filepath:
            try:
                with open(filepath, "wb") as key_file:
                    key_file.write(self.active_key)
                messagebox.showinfo("Success", f"Active key saved to {filepath}")
            except Exception as e:
                messagebox.showerror("Save Failed", f"Could not save the key file: {e}")

    def encrypt_text_action(self):
        text_to_encrypt = self.text_input.get("1.0", tk.END).strip()
        if not text_to_encrypt:
            messagebox.showerror("Error", "Please enter text to encrypt.")
            return

        key_to_use = self.active_key
        if key_to_use is None:
            password = self.text_password_entry.get()
            if not password:
                messagebox.showerror("Error", "Please provide a password or activate a key in the 'Manage Key' tab.")
                return
            key_to_use = derive_key_from_password(password, self.text_salt)

        try:
            encrypted_text = encrypt_text(text_to_encrypt, key_to_use)
            self.text_input.delete("1.0", tk.END)
            self.text_input.insert("1.0", encrypted_text)
            messagebox.showinfo("Success", "Text encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Encryption Failed", str(e))

    def decrypt_text_action(self):
        text_to_decrypt = self.text_input.get("1.0", tk.END).strip()
        if not text_to_decrypt:
            messagebox.showerror("Error", "Please enter text to decrypt.")
            return

        key_to_use = self.active_key
        if key_to_use is None:
            password = self.text_password_entry.get()
            if not password:
                messagebox.showerror("Error", "Please provide a password or activate a key in the 'Manage Key' tab.")
                return
            key_to_use = derive_key_from_password(password, self.text_salt)

        try:
            decrypted_text = decrypt_text(text_to_decrypt, key_to_use)
            self.text_input.delete("1.0", tk.END)
            self.text_input.insert("1.0", decrypted_text)
            messagebox.showinfo("Success", "Text decrypted successfully!")
        except Exception as e:
            messagebox.showerror("Decryption Failed", "Decryption failed. Check the key/password or input text.")

    def copy_to_clipboard(self):
        self.clipboard_clear()
        self.clipboard_append(self.text_input.get("1.0", tk.END).strip())
        messagebox.showinfo("Copied", "Text copied to clipboard!")

    def select_input_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.input_file_path.set(filepath)

    def encrypt_file_action(self):
        input_path = self.input_file_path.get()
        if not input_path:
            messagebox.showerror("Error", "Please select a file.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".enc", initialfile=os.path.basename(input_path) + ".enc")
        if not output_path:
            return

        self.progress["value"] = 0
        self.update_idletasks()

        def task():
            try:
                key_to_use = self.active_key
                password = self.file_password_entry.get()

                if key_to_use:
                    with open(input_path, "rb") as in_f, open(output_path, "wb") as out_f:
                        _encrypt_stream(in_f, out_f, key_to_use)
                    messagebox.showinfo("Success", f"File encrypted successfully to {output_path}")
                elif password:
                    with open(input_path, "rb") as in_f, open(output_path, "wb") as out_f:
                        encrypt_file_with_password(in_f, password, out_f)
                    messagebox.showinfo("Success", f"File encrypted successfully to {output_path}")
                else:
                    messagebox.showerror("Error", "Please provide a password or activate a key in the 'Manage Key' tab.")
                    return
                
                self.progress["value"] = 100
            except Exception as e:
                messagebox.showerror("Encryption Failed", str(e))
            finally:
                self.progress["value"] = 0
        threading.Thread(target=task).start()

    def decrypt_file_action(self):
        input_path = self.input_file_path.get()
        if not input_path:
            messagebox.showerror("Error", "Please select a file.")
            return

        suggested_name = os.path.basename(input_path).rsplit('.enc', 1)[0] if input_path.endswith('.enc') else os.path.basename(input_path) + ".dec"
        output_path = filedialog.asksaveasfilename(initialfile=suggested_name)
        if not output_path:
            return

        self.progress["value"] = 0
        self.update_idletasks()

        def task():
            try:
                key_to_use = self.active_key
                password = self.file_password_entry.get()

                if key_to_use:
                    with open(input_path, "rb") as in_f, open(output_path, "wb") as out_f:
                        _decrypt_stream(in_f, out_f, key_to_use)
                    messagebox.showinfo("Success", f"File decrypted successfully to {output_path}")
                elif password:
                    with open(input_path, "rb") as in_f, open(output_path, "wb") as out_f:
                        decrypt_file_with_password(in_f, password, out_f)
                    messagebox.showinfo("Success", f"File decrypted successfully to {output_path}")
                else:
                    messagebox.showerror("Error", "Please provide a password or activate a key in the 'Manage Key' tab.")
                    return

                self.progress["value"] = 100
            except Exception as e:
                messagebox.showerror("Decryption Failed", "Decryption failed. Check the key/password or file integrity.")
            finally:
                self.progress["value"] = 0
        threading.Thread(target=task).start()

if __name__ == "__main__":
    app = EncryptorApp()
    app.mainloop()
