from PIL import Image
import numpy as np
import hashlib
import os
from tqdm import tqdm
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import logging
from datetime import datetime

class ImageEncryptor:
    def __init__(self, key, rounds=1, algorithm='basic'):
        self.rounds = max(1, min(rounds, 5))
        self.algorithm = algorithm
        self._initialize_key(key)
    
    def _initialize_key(self, key):
        if os.path.isfile(key):
            with open(key, 'rb') as f:
                key_data = f.read()
        else:
            key_data = key.encode()
        
        hash_obj = hashlib.sha256(key_data)
        self.seed = int(hash_obj.hexdigest(), 16) % 2**32
        np.random.seed(self.seed)
        self.xor_keys = np.random.randint(0, 256, size=3, dtype=np.uint8)
    
    def _generate_swap_map(self, size):
        indices = np.arange(size)
        np.random.seed(self.seed)
        np.random.shuffle(indices)
        return indices
    
    def _advanced_transform(self, array):
        # Additional transformation for advanced algorithm
        return np.roll(array, shift=self.seed % 8, axis=0)
    
    def encrypt(self, image_path, output_path):
        try:
            img = Image.open(image_path).convert('RGB')
            pixel_array = np.array(img)
            height, width, _ = pixel_array.shape
            
            working_array = pixel_array.copy()
            for _ in tqdm(range(self.rounds), desc="Encrypting rounds"):
                working_array = working_array ^ self.xor_keys
                flat_array = working_array.reshape(-1, 3)
                swap_map = self._generate_swap_map(len(flat_array))
                flat_array = flat_array[swap_map]
                working_array = flat_array.reshape(height, width, 3)
                if self.algorithm == 'advanced':
                    working_array = self._advanced_transform(working_array)
            
            result_img = Image.fromarray(working_array)
            result_img.save(output_path)
            logging.info(f"Encrypted {image_path} to {output_path}")
            return True, f"Encrypted image saved to {output_path}"
        
        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            return False, f"Encryption error: {str(e)}"
    
    def decrypt(self, image_path, output_path):
        try:
            img = Image.open(image_path).convert('RGB')
            pixel_array = np.array(img)
            height, width, _ = pixel_array.shape
            
            working_array = pixel_array.copy()
            for _ in tqdm(range(self.rounds), desc="Decrypting rounds"):
                if self.algorithm == 'advanced':
                    working_array = np.roll(working_array, shift=-(self.seed % 8), axis=0)
                flat_array = working_array.reshape(-1, 3)
                swap_map = self._generate_swap_map(len(flat_array))
                inverse_map = np.zeros_like(swap_map)
                inverse_map[swap_map] = np.arange(len(swap_map))
                flat_array = flat_array[inverse_map]
                working_array = flat_array.reshape(height, width, 3)
                working_array = working_array ^ self.xor_keys
            
            result_img = Image.fromarray(working_array)
            result_img.save(output_path)
            logging.info(f"Decrypted {image_path} to {output_path}")
            return True, f"Decrypted image saved to {output_path}"
        
        except Exception as e:
            logging.error(f"Decryption failed: {str(e)}")
            return False, f"Decryption error: {str(e)}"

class ImageEncryptorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Image Encryption Tool")
        self.root.geometry("600x550")
        self.root.resizable(False, False)
        
        # Configure logging
        logging.basicConfig(filename='image_encryptor.log', 
                          level=logging.INFO,
                          format='%(asctime)s - %(levelname)s - %(message)s')

        # Style configuration
        style = ttk.Style()
        style.configure("TButton", padding=6)
        style.configure("TLabel", padding=3)
        style.configure("Header.TLabel", font=('Helvetica', 12, 'bold'))

        # Main container
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Main tab
        self.main_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.main_frame, text="Encryption")

        # History tab
        self.history_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.history_frame, text="History")

        self.setup_main_tab()
        self.setup_history_tab()

    def setup_main_tab(self):
        # Header
        ttk.Label(self.main_frame, text="Image Encryption", style="Header.TLabel").grid(row=0, column=0, columnspan=3, pady=10)

        # Key frame
        key_frame = ttk.LabelFrame(self.main_frame, text="Key Settings", padding=5)
        key_frame.grid(row=1, column=0, columnspan=3, pady=5, sticky="ew")
        
        ttk.Label(key_frame, text="Key:").grid(row=0, column=0, sticky=tk.W)
        self.key_entry = ttk.Entry(key_frame, width=40)
        self.key_entry.grid(row=0, column=1, padx=5)
        ttk.Button(key_frame, text="Browse", command=self.browse_key).grid(row=0, column=2)

        # Algorithm selection
        ttk.Label(key_frame, text="Algorithm:").grid(row=1, column=0, sticky=tk.W)
        self.algorithm_var = tk.StringVar(value="basic")
        ttk.Radiobutton(key_frame, text="Basic", variable=self.algorithm_var, value="basic").grid(row=1, column=1, sticky=tk.W)
        ttk.Radiobutton(key_frame, text="Advanced", variable=self.algorithm_var, value="advanced").grid(row=1, column=2, sticky=tk.W)

        # Rounds
        ttk.Label(key_frame, text="Rounds:").grid(row=2, column=0, sticky=tk.W)
        self.rounds_spinbox = ttk.Spinbox(key_frame, from_=1, to=5, width=5)
        self.rounds_spinbox.set(1)
        self.rounds_spinbox.grid(row=2, column=1, sticky=tk.W, pady=5)

        # File frame
        file_frame = ttk.LabelFrame(self.main_frame, text="File Settings", padding=5)
        file_frame.grid(row=2, column=0, columnspan=3, pady=5, sticky="ew")
        
        ttk.Label(file_frame, text="Input:").grid(row=0, column=0, sticky=tk.W)
        self.input_entry = ttk.Entry(file_frame, width=40)
        self.input_entry.grid(row=0, column=1, padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_input).grid(row=0, column=2)

        ttk.Label(file_frame, text="Output:").grid(row=1, column=0, sticky=tk.W)
        self.output_entry = ttk.Entry(file_frame, width=40)
        self.output_entry.grid(row=1, column=1, padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_output).grid(row=1, column=2)

        # Progress and status
        self.progress = ttk.Progressbar(self.main_frame, length=400, mode='determinate')
        self.progress.grid(row=3, column=0, columnspan=3, pady=10)
        
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.main_frame, textvariable=self.status_var).grid(row=4, column=0, columnspan=3)

        # Buttons
        button_frame = ttk.Frame(self.main_frame)
        button_frame.grid(row=5, column=0, columnspan=3, pady=10)
        self.encrypt_btn = ttk.Button(button_frame, text="Encrypt", command=self.encrypt)
        self.encrypt_btn.grid(row=0, column=0, padx=5)
        self.decrypt_btn = ttk.Button(button_frame, text="Decrypt", command=self.decrypt)
        self.decrypt_btn.grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_fields).grid(row=0, column=2, padx=5)

        self.main_frame.columnconfigure(1, weight=1)

    def setup_history_tab(self):
        ttk.Label(self.history_frame, text="Operation History", style="Header.TLabel").pack(pady=10)
        
        self.history_text = tk.Text(self.history_frame, height=20, width=60, state='disabled')
        self.history_text.pack(padx=5, pady=5)
        
        ttk.Button(self.history_frame, text="Refresh History", command=self.load_history).pack(pady=5)
        self.load_history()

    def browse_key(self):
        filename = filedialog.askopenfilename(title="Select Key File")
        if filename:
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, filename)

    def browse_input(self):
        filename = filedialog.askopenfilename(
            title="Select Input Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")]
        )
        if filename:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, filename)
            # Auto-fill output with same name + suffix
            output_name = os.path.splitext(filename)[0] + "_enc.png"
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, output_name)

    def browse_output(self):
        filename = filedialog.asksaveasfilename(
            title="Save Output As",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("JPEG files", "*.jpg"), ("BMP files", "*.bmp")]
        )
        if filename:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, filename)

    def clear_fields(self):
        self.key_entry.delete(0, tk.END)
        self.input_entry.delete(0, tk.END)
        self.output_entry.delete(0, tk.END)
        self.rounds_spinbox.set(1)
        self.algorithm_var.set("basic")
        self.status_var.set("Ready")
        self.progress['value'] = 0

    def load_history(self):
        self.history_text.config(state='normal')
        self.history_text.delete(1.0, tk.END)
        try:
            with open('image_encryptor.log', 'r') as f:
                self.history_text.insert(tk.END, f.read())
        except FileNotFoundError:
            self.history_text.insert(tk.END, "No history available yet.")
        self.history_text.config(state='disabled')

    def process_action(self, action):
        key = self.key_entry.get()
        rounds = int(self.rounds_spinbox.get())
        algorithm = self.algorithm_var.get()
        input_path = self.input_entry.get()
        output_path = self.output_entry.get()

        if not all([key, input_path, output_path]):
            messagebox.showerror("Error", "Please fill in all required fields")
            return

        self.encrypt_btn.state(['disabled'])
        self.decrypt_btn.state(['disabled'])
        self.status_var.set(f"{'Encrypting' if action == 'encrypt' else 'Decrypting'}...")
        self.progress['value'] = 0

        def process():
            encryptor = ImageEncryptor(key, rounds, algorithm)
            total_steps = rounds
            if action == "encrypt":
                success, message = encryptor.encrypt(input_path, output_path)
            else:
                success, message = encryptor.decrypt(input_path, output_path)
            
            for i in range(total_steps):
                self.root.after(i * 100, lambda x=i+1: self.progress.configure(value=(x/total_steps)*100))
            
            self.root.after(total_steps * 100, lambda: self.finish_process(success, message))

        threading.Thread(target=process, daemon=True).start()

    def finish_process(self, success, message):
        self.encrypt_btn.state(['!disabled'])
        self.decrypt_btn.state(['!disabled'])
        self.status_var.set("Ready")
        
        if success:
            messagebox.showinfo("Success", message)
            self.load_history()
        else:
            messagebox.showerror("Error", message)

    def encrypt(self):
        self.process_action("encrypt")

    def decrypt(self):
        self.process_action("decrypt")

def main():
    root = tk.Tk()
    app = ImageEncryptorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()