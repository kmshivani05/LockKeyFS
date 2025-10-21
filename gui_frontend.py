import subprocess
import os
import tkinter as tk
from tkinter import messagebox


# CONFIGURATION
BACKING_DIR = os.path.expanduser("~/lock_key_fs/backing")
MOUNTPOINT = os.path.expanduser("~/lock_key_fs/mountpoint")
LOCKKEY_EXEC = os.path.expanduser("~/lock_key_fs/lockkeyfs")


# FUNCTIONS
def mount_fs():
    """Mounts the encrypted filesystem after asking for passphrase."""
    try:
        password = password_entry.get().strip()  # Get user-entered passphrase
        if not password:
            messagebox.showwarning("Missing Passphrase", "Please enter your passphrase!")
            return

        # Debug print (not shown in final system)
        print(f"Passphrase entered: {password}")

        # Check if folders exist
        if not os.path.exists(BACKING_DIR) or not os.path.exists(MOUNTPOINT):
            messagebox.showerror("Error", "Backing or mountpoint folder not found.")
            return

        # Run lockkeyfs in FOREGROUND mode (-f) so it stays mounted
        subprocess.Popen(
            [LOCKKEY_EXEC, BACKING_DIR, MOUNTPOINT, "--key="+password,"-f", "-o", "nonempty"]
        )

        messagebox.showinfo("Mounted", "Filesystem mounted successfully!")
        status_label.config(text="Status: Mounted✅", fg="green")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to mount filesystem.\n{e}")

def unmount_fs():
    """Unmounts the filesystem."""
    try:
        subprocess.run(["fusermount", "-u", MOUNTPOINT])
        messagebox.showinfo("Unmounted", "Filesystem unmounted successfully!")
        status_label.config(text="Status: Unmounted ❌", fg="red")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to unmount filesystem.\n{e}")

def open_mount_folder():
    """Opens the mountpoint folder in file explorer."""
    if os.path.ismount(MOUNTPOINT):
        subprocess.Popen(["xdg-open", MOUNTPOINT])
    else:
        messagebox.showwarning("Warning", "Filesystem is not mounted!")

def check_status():
    """Checks if filesystem is mounted and updates label."""
    if os.path.ismount(MOUNTPOINT):
        status_label.config(text="Status: Mounted ✅", fg="green")
    else:
        status_label.config(text="Status: Unmounted ❌", fg="red")


# GUI LAYOUT (Tkinter)

root = tk.Tk()
root.title("🔐 Lock & Key Filesystem Control Panel")
root.geometry("440x380")
root.resizable(False, False)
root.configure(bg="#f4f4f4")

# Title
tk.Label(root, text="Lock & Key Encrypted Filesystem", 
         font=("Helvetica", 14, "bold"), bg="#f4f4f4").pack(pady=15)

# Directory info
tk.Label(root, text=f"Backing Dir: {BACKING_DIR}", bg="#f4f4f4").pack()
tk.Label(root, text=f"Mountpoint: {MOUNTPOINT}", bg="#f4f4f4").pack(pady=(0,10))

# Passphrase input
tk.Label(root, text="Enter Passphrase:", bg="#f4f4f4").pack()
password_entry = tk.Entry(root, width=35, show="*")
password_entry.pack(pady=5)

# Buttons
tk.Button(root, text="🔒 Mount Filesystem", width=20, bg="#0078D7", fg="white", 
          command=mount_fs).pack(pady=6)
tk.Button(root, text="🔓 Unmount Filesystem", width=20, bg="#FF5252", fg="white", 
          command=unmount_fs).pack(pady=6)
tk.Button(root, text="📂 Open Mount Folder", width=20, bg="#FFA500", fg="white", 
          command=open_mount_folder).pack(pady=6)
tk.Button(root, text="🔄 Refresh Status", width=20, bg="#4CAF50", fg="white", 
          command=check_status).pack(pady=8)

# Status
status_label = tk.Label(root, text="Status: Unknown", 
                        font=("Helvetica", 12), bg="#f4f4f4", fg="black")
status_label.pack(pady=10)
check_status()

# Exit
tk.Button(root, text="Exit", width=10, bg="gray", fg="white", 
          command=root.destroy).pack(pady=10)

# Run GUI
root.mainloop()
