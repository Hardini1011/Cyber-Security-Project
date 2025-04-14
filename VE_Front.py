import tkinter as tk
from tkinter import filedialog, messagebox
from ttkthemes import ThemedTk
import Visual_Encryption  # Your backend file
import re

# Function to check password strength
def check_password_strength(password):
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*()-_=+]", password):
        errors.append("Password must contain at least one special character (!@#$%^&*()-_=+).")
    
    if errors:
        messagebox.showerror("Weak Password", "\n".join(errors))
        return False
    return True

# Function to handle encryption
def encrypt_image():
    file_path = filedialog.askopenfilename(title="Select an Image")
    if not file_path:
        return
    key = key_entry.get()
    if not key:
        messagebox.showerror("Error", "Please enter an encryption key!")
        return
    
    Visual_Encryption.encrypt_image(file_path, key)
    messagebox.showinfo("Success", "Image Encrypted Successfully!")

# Function to handle decryption
def decrypt_image():
    file_path = filedialog.askopenfilename(title="Select Encrypted File")
    if not file_path:
        return
    key = key_entry.get()
    if not key:
        messagebox.showerror("Error", "Please enter a decryption key!")
        return
    
    Visual_Encryption.decrypt_image(file_path, key)
    messagebox.showinfo("Success", "Image Decrypted Successfully!")

# Function to show encryption UI after login
def show_main_ui():
    login_frame.pack_forget()
    main_frame.pack()

# Function to handle login
def login():
    username = username_entry.get().strip()
    password = password_entry.get()
    if not username or not password:
        messagebox.showerror("Error", "Username and password cannot be empty!")
        return
    
    if check_password_strength(password):
        messagebox.showinfo("Success", f"Welcome, {username}! You are now logged in.")
        show_main_ui()

# Main Window
root = ThemedTk(theme="breeze")
root.title("🛡 Secure Image Encryptor")
root.geometry("500x600")
root.config(bg="#1f1f2e")

# Login Frame
login_frame = tk.Frame(root, bg="#1f1f2e")
login_frame.pack()

tk.Label(login_frame, text="Login", font=("Arial", 18, "bold"), fg="white", bg="#1f1f2e").pack(pady=10)

tk.Label(login_frame, text="Username:", font=("Arial", 12), fg="white", bg="#1f1f2e").pack()
username_entry = tk.Entry(login_frame, font=("Arial", 14), width=30)
username_entry.pack(pady=5)

tk.Label(login_frame, text="Password:", font=("Arial", 12), fg="white", bg="#1f1f2e").pack()
password_entry = tk.Entry(login_frame, show="*", font=("Arial", 14), width=30)
password_entry.pack(pady=5)

login_btn = tk.Button(login_frame, text="🔑 Login", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", padx=20, pady=10, command=login)
login_btn.pack(pady=10)

# Main UI Frame (Hidden initially)
main_frame = tk.Frame(root, bg="#1f1f2e")

tk.Label(main_frame, text="Secure Image Encryptor", font=("Arial", 18, "bold"), fg="white", bg="#1f1f2e").pack()

tk.Label(main_frame, text="Enter Encryption Key:", font=("Arial", 12), fg="white", bg="#1f1f2e").pack(pady=5)
key_entry = tk.Entry(main_frame, show="*", font=("Arial", 14), width=30)
key_entry.pack(pady=5)

encrypt_btn = tk.Button(main_frame, text="🔒 Encrypt Image", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", padx=20, pady=10, command=encrypt_image)
encrypt_btn.pack(pady=10)

decrypt_btn = tk.Button(main_frame, text="🔓 Decrypt Image", font=("Arial", 12, "bold"), bg="#f44336", fg="white", padx=20, pady=10, command=decrypt_image)
decrypt_btn.pack(pady=10)

exit_btn = tk.Button(main_frame, text="🚪 Exit", font=("Arial", 12, "bold"), bg="#607d8b", fg="white", padx=20, pady=10, command=root.quit)
exit_btn.pack(pady=10)

root.mainloop()
