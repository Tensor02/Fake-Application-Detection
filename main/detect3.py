import hashlib
import os
import subprocess
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
from PIL import Image, ImageTk

# Define apk_path_entry and result_label as global variables
apk_path_entry = None
result_label = None
main_window = None
login_window = None
apk_details_window = None

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
    metadata = get_apk_metadata(apk_path)
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
    global apk_details_window
    apk_path = apk_path_entry.get()
    if apk_path:
        result = detect_fake_apk(apk_path)
        if result == "Official":
            result_label.config(text="APK is Official")
        else:
            result_label.config(text="APK is Fake")
            apk_details_window = show_apk_details(apk_path)

# Function to create the login GUI
def create_login_gui():
    global login_window
    login_window = tk.Tk()
    login_window.title("Login")
    login_window.geometry("800x600")

    background_image = Image.open("../data/img_1.png")
    background_image = background_image.resize((800, 600))
    photo = ImageTk.PhotoImage(background_image)

    background_label = tk.Label(login_window, image=photo)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    login_frame = ttk.Frame(login_window)
    login_frame.pack(padx=20, pady=20)

    login_label = ttk.Label(login_frame, text="Admin Login", font=("Arial", 20), foreground="white", background="black")
    login_label.grid(row=0, column=0, columnspan=2, pady=20)

    username_label = ttk.Label(login_frame, text="Username:", font=("Arial", 16), foreground="white", background="black")
    username_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
    username_entry = ttk.Entry(login_frame, font=("Arial", 16))
    username_entry.grid(row=1, column=1, padx=5, pady=5)

    password_label = ttk.Label(login_frame, text="Password:", font=("Arial", 16), foreground="white", background="black")
    password_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
    password_entry = ttk.Entry(login_frame, show="*", font=("Arial", 16))
    password_entry.grid(row=2, column=1, padx=5, pady=5)

    def authenticate():
        if username_entry.get() == "admin" and password_entry.get() == "admin":
            login_window.destroy()
            create_main_gui()
        else:
            error_label.config(text="Invalid username or password")

    login_button = ttk.Button(login_frame, text="Login", command=authenticate, style='TButton')
    login_button.grid(row=3, column=0, columnspan=2, pady=20)

    error_label = ttk.Label(login_frame, text="", font=("Arial", 14), foreground="red", background="black")
    error_label.grid(row=4, column=0, columnspan=2)

    login_window.mainloop()

# Function to create the main GUI
def create_main_gui():
    global main_window
    main_window = tk.Tk()
    main_window.title("APK Verifier")
    main_window.geometry("800x600")

    background_image = Image.open("../data/img_1.png")
    background_image = background_image.resize((800, 600))
    photo = ImageTk.PhotoImage(background_image)

    background_label = tk.Label(main_window, image=photo)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    main_frame = ttk.Frame(main_window)
    main_frame.pack(padx=20, pady=20)

    browse_button = ttk.Button(main_frame, text="Browse APK", command=browse_file, style='TButton')
    browse_button.grid(row=0, column=0, pady=20)

    global apk_path_entry
    apk_path_entry = ttk.Entry(main_frame, width=50, font=("Arial", 16))
    apk_path_entry.grid(row=1, column=0, pady=10)

    verify_button = ttk.Button(main_frame, text="Verify APK", command=verify_apk, style='TButton')
    verify_button.grid(row=2, column=0, pady=20)

    global result_label
    result_label = ttk.Label(main_frame, text="", font=("Arial", 20), foreground="white", background="black")
    result_label.grid(row=3, column=0)

    main_window.mainloop()

# Function to show APK details
def show_apk_details(apk_path):
    global apk_details_window
    apk_name = os.path.basename(apk_path)
    if apk_details_window:
        apk_details_window.destroy()
    apk_details_window = tk.Toplevel(main_window)
    apk_details_window.title("APK Details")
    apk_details_window.geometry("800x600")

    background_image = Image.open("../data/img_1.png")
    background_image = background_image.resize((800, 600))
    photo = ImageTk.PhotoImage(background_image)

    background_label = tk.Label(apk_details_window, image=photo)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    apk_details_frame = ttk.Frame(apk_details_window)
    apk_details_frame.pack(padx=20, pady=20)

    apk_name_label = ttk.Label(apk_details_frame, text=f"APK Name: {apk_name}",
                               font=("Arial", 16), foreground="white", background="black")
    apk_name_label.grid(row=0, column=0, pady=10)

    apk_path_label = ttk.Label(apk_details_frame, text=f"APK Path: {apk_path}",
                               font=("Arial", 16), foreground="white", background="black")
    apk_path_label.grid(row=1, column=0, pady=10)

    # Retrieve metadata using the placeholder function
    metadata = get_apk_metadata(apk_path)
    metadata_label = ttk.Label(apk_details_frame, text=f"Metadata: {metadata}",
                               font=("Arial", 16), foreground="white", background="black")
    metadata_label.grid(row=2, column=0, pady=10)

# Function to extract metadata from APK file
def get_apk_metadata(apk_path):
    try:
        # Run the 'aapt dump badging' command to extract metadata
        output = subprocess.check_output(['aapt', 'dump', 'badging', apk_path]).decode('utf-8').split('\n')
        # Extract package name, version code, and version name from the output
        package_name = output[0].split("'")[1]
        version_code = output[0].split("versionCode='")[1].split("'")[0]
        version_name = output[0].split("versionName='")[1].split("'")[0]
        return {
            'package_name': package_name,
            'version_code': version_code,
            'version_name': version_name
        }
    except subprocess.CalledProcessError:
        return "Error extracting metadata"

# Main function
def main():
    create_login_gui()

if __name__ == "__main__":
    main()
