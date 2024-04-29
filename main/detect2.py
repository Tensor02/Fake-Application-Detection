import hashlib
import subprocess
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk

# Define apk_path_entry and result_label as global variables
apk_path_entry = None
result_label = None

# Function to calculate APK checksum
def calculate_apk_checksum(apk_path):
    with open(apk_path, "rb") as f:
        checksum = hashlib.sha256(f.read()).hexdigest()
    return checksum

# Function to verify APK signature
def verify_apk_signature(apk_path):
    try:
        result = subprocess.run(["jarsigner", "-verify", "-verbose", apk_path], capture_output=True, check=True)
        return "verified" in result.stdout.decode().lower()
    except subprocess.CalledProcessError:
        return False

# Function to detect fake APK
def detect_fake_apk(apk_path):
    # Placeholder for the original checksum and package name
    ORIGINAL_APK_CHECKSUM = "original_checksum_here"
    ORIGINAL_PACKAGE_NAME = "original_package_name_here"

    checksum = calculate_apk_checksum(apk_path)
    if checksum != ORIGINAL_APK_CHECKSUM:
        return "Checksum mismatch"

    if not verify_apk_signature(apk_path):
        return "Signature verification failed"

    # Placeholder for metadata extraction
    metadata = {"package_name": "placeholder"}
    if metadata['package_name'] != ORIGINAL_PACKAGE_NAME:
        return "Package name mismatch"

    # Placeholder for source verification
    if not is_apk_from_official_source(apk_path):
        return "Not from official source"

    return "Official"

# Function to handle file selection
def browse_file():
    global apk_path_entry
    filepath = filedialog.askopenfilename(initialdir="/", title="Select APK File", filetypes=(("APK files", "*.apk"), ("all files", "*.*")))
    if filepath:
        apk_path_entry.delete(0, tk.END)
        apk_path_entry.insert(tk.END, filepath)
        result_label.config(text="")

# Function to handle APK verification
def verify_apk():
    global apk_path_entry
    global result_label
    apk_path = apk_path_entry.get()
    if apk_path:
        result = detect_fake_apk(apk_path)
        result_label.config(text=result)

# Function to create the login GUI
def create_login_gui():
    # Login window
    login_window = tk.Tk()
    login_window.title("Login")

    login_frame = ttk.Frame(login_window)
    login_frame.pack(padx=20, pady=20)

    login_label = ttk.Label(login_frame, text="Admin Login", font=("Arial", 14))
    login_label.grid(row=0, column=0, columnspan=2, pady=10)

    username_label = ttk.Label(login_frame, text="Username:")
    username_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
    username_entry = ttk.Entry(login_frame)
    username_entry.grid(row=1, column=1, padx=5, pady=5)

    password_label = ttk.Label(login_frame, text="Password:")
    password_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
    password_entry = ttk.Entry(login_frame, show="*")
    password_entry.grid(row=2, column=1, padx=5, pady=5)

    def authenticate():
        if username_entry.get() == "admin" and password_entry.get() == "admin":
            login_window.destroy()
            create_main_gui()
        else:
            error_label.config(text="Invalid username or password")

    login_button = ttk.Button(login_frame, text="Login", command=authenticate)
    login_button.grid(row=3, column=0, columnspan=2, pady=10)

    error_label = tk.Label(login_frame, text="", fg="red")
    error_label.grid(row=4, column=0, columnspan=2)

    login_window.mainloop()

# Function to create the main GUI
def create_main_gui():
    global apk_path_entry
    global result_label
    # Main window
    main_window = tk.Tk()
    main_window.title("APK Verifier")

    main_frame = ttk.Frame(main_window)
    main_frame.pack(padx=20, pady=20)

    browse_button = ttk.Button(main_frame, text="Browse APK", command=browse_file)
    browse_button.grid(row=0, column=0, pady=10)

    apk_path_entry = ttk.Entry(main_frame, width=50)
    apk_path_entry.grid(row=1, column=0, pady=5)

    verify_button = ttk.Button(main_frame, text="Verify APK", command=verify_apk)
    verify_button.grid(row=2, column=0, pady=10)

    result_label = ttk.Label(main_frame, text="")
    result_label.grid(row=3, column=0)

    main_window.mainloop()

# Main function
def main():
    create_login_gui()

if __name__ == "__main__":
    main()
