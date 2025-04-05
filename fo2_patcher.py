import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
from pathlib import Path

class PatcherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Fallout 2 Patcher")
        self.exe_data = None
        self.exe_path = None
        self.patches = {}
        
        # Top Label Frame
        frame = ttk.Frame(root, padding=(10, 0))
        frame.grid(row=0, column=0, sticky="w")
        ttk.Label(frame, text="Select your fallout2 exe:").pack(side=tk.LEFT)

        # EXE Entry Frame
        exe_frame = ttk.Frame(root, padding=(10, 0))
        exe_frame.grid(row=1, column=0, sticky="ew")
        self.exe_entry = ttk.Entry(exe_frame, width=40)
        self.exe_entry.config(state='disabled')
        self.exe_entry.pack(side=tk.LEFT, padx=5)

        # Buttons Frame (now includes Select at top)
        button_frame = ttk.Frame(root, padding=(5, 0))
        button_frame.grid(row=1, column=1, rowspan=2, sticky="n")
        ttk.Button(button_frame, text="Select", command=self.select_exe).pack(padx=5, pady=(0, 20))  # Top gap for separation
        ttk.Button(button_frame, text="Inspect", command=self.inspect_patch).pack(padx=5, pady=5)
        ttk.Button(button_frame, text="Apply", command=self.apply_patch).pack(padx=5, pady=5)
        ttk.Button(button_frame, text="Remove", command=self.remove_patch).pack(padx=5, pady=5)
        ttk.Button(button_frame, text="Save As", command=self.save_as).pack(padx=5, pady=30)

        # Patch List Frame
        patch_frame = ttk.Frame(root, padding=(10, 0))
        patch_frame.grid(row=2, column=0, sticky="nsew")
        self.patch_listbox = tk.Listbox(patch_frame, height=15, width=40)
        self.patch_listbox.pack(side=tk.LEFT, fill=tk.Y)
        scrollbar = ttk.Scrollbar(patch_frame, orient="vertical")
        scrollbar.config(command=self.patch_listbox.yview)
        self.patch_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y)


        # CRC Display Frame
        crc_frame = ttk.Frame(root, padding=(10, 10))
        crc_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
        ttk.Label(crc_frame, text="CRC (add to ddraw.ini):").grid(row=0, column=0, sticky="w")
        self.crc_entry = ttk.Entry(crc_frame, width=40)
        self.crc_entry.config(state='readonly')
        self.crc_entry.grid(row=0, column=1, padx=5)

        # Load available patches
        self.load_patches()
        

    def load_patches(self):
        self.patch_listbox.delete(0, tk.END)
        self.patches.clear()
        current_dir = Path(__file__).parent
        
        for file in current_dir.glob("*.patch"):
            with open(file, 'r') as f:
                patch_data = []
                for line in f:
                    if line.strip():
                        addr, orig, new = [int(x, 16) for x in line.strip().split(',')]
                        patch_data.append((addr, orig, new))
                self.patches[file.name] = patch_data
                self.patch_listbox.insert(tk.END, file.name)

    def select_exe(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")],
            title="Select Fallout 2 executable"
        )
        if file_path:
            self.exe_path = file_path
            self.exe_entry.config(state='normal')
            self.exe_entry.delete(0, tk.END)
            self.exe_entry.insert(0, file_path)
            self.exe_entry.config(state='disabled')
            with open(file_path, 'rb') as f:
                self.exe_data = bytearray(f.read())
            self.update_crc()

    def get_selected_patch(self):
        selection = self.patch_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a patch first")
            return None
        patch_name = self.patch_listbox.get(selection[0])
        return patch_name

    def inspect_patch(self):
        if not self.exe_data:
            messagebox.showerror("Error", "Please select an executable first")
            return
            
        patch_name = self.get_selected_patch()
        if not patch_name:
            return
            
        patch_data = self.patches[patch_name]
        status = []
        
        for addr, orig, new in patch_data:
            current = self.exe_data[addr]
            if current == new:
                status.append(f"0x{addr:08x}: Already patched")
            elif current == orig:
                status.append(f"0x{addr:08x}: Original")
            else:
                status.append(f"0x{addr:08x}: Mismatch (expected 0x{orig:02x}, got 0x{current:02x})")
        
        messagebox.showinfo(f"Inspect: {patch_name}", "\n".join(status))

    def apply_patch(self):
        if not self.exe_data:
            messagebox.showerror("Error", "Please select an executable first")
            return
            
        patch_name = self.get_selected_patch()
        if not patch_name:
            return
            
        patch_data = self.patches[patch_name]
        for addr, orig, new in patch_data:
            self.exe_data[addr] = new
        self.update_crc()
        messagebox.showinfo("Success", f"Patch {patch_name} applied successfully")

    def remove_patch(self):
        if not self.exe_data:
            messagebox.showerror("Error", "Please select an executable first")
            return
            
        patch_name = self.get_selected_patch()
        if not patch_name:
            return
            
        patch_data = self.patches[patch_name]
        for addr, orig, new in patch_data:
            self.exe_data[addr] = orig
        self.update_crc()
        messagebox.showinfo("Success", f"Patch {patch_name} removed successfully")

    def save_as(self):
        if not self.exe_data:
            messagebox.showerror("Error", "Please select an executable first")
            return
            
        save_path = filedialog.asksaveasfilename(
            defaultextension=".exe",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")],
            title="Save patched executable as"
        )
        if save_path:
            with open(save_path, 'wb') as f:
                f.write(self.exe_data)
            messagebox.showinfo("Success", "File saved successfully")

    def update_crc(self):
        crc = 0xFFFFFFFF
        polynomial = 0x1EDC6F41
        
        for byte in self.exe_data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ polynomial
                else:
                    crc >>= 1
          
        crc_value = f'0x{crc ^ 0xFFFFFFFF:08x}'
        self.crc_entry.config(state='normal')
        self.crc_entry.delete(0, tk.END)
        self.crc_entry.insert(0, crc_value)
        self.crc_entry.config(state='readonly')


if __name__ == "__main__":
    root = tk.Tk()
    app = PatcherApp(root)
    root.mainloop()