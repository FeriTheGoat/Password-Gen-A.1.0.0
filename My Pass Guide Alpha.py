import random
import string
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import secrets
import hashlib

class PasswordGeneratorUI:
    def __init__(self):
        # Configure theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Create main window
        self.root = ctk.CTk()
        self.root.title("Secure Password Generator")
        self.root.geometry("800x800")
        
        # Create header
        header_frame = ctk.CTkFrame(self.root)
        header_frame.pack(pady=20, padx=20, fill="x")
        
        ctk.CTkLabel(
            header_frame, 
            text="Advanced Password Generator", 
            font=("Roboto", 24, "bold")
        ).pack()
        
        # Create main content frame
        content_frame = ctk.CTkFrame(self.root)
        content_frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        # Input fields
        self.name_var = tk.StringVar()
        self.age_var = tk.StringVar() 
        self.website_var = tk.StringVar()
        self.phrases_var = tk.StringVar()
        self.max_length_var = tk.StringVar()
        self.algorithm_var = tk.StringVar(value="Standard")
        
        # Create input fields
        self.create_input_field(content_frame, "Name/Username:", self.name_var)
        self.create_input_field(content_frame, "Age:", self.age_var)
        self.create_input_field(content_frame, "Website:", self.website_var)
        self.create_input_field(content_frame, "Phrases (comma separated):", self.phrases_var)
        self.create_input_field(content_frame, "Max Length (optional):", self.max_length_var)
        
        # Algorithm selector
        algo_frame = ctk.CTkFrame(content_frame)
        algo_frame.pack(pady=10, fill="x", padx=20)
        
        ctk.CTkLabel(
            algo_frame,
            text="Algorithm:",
            font=("Roboto", 12)
        ).pack(side="left")
        
        algorithms = ["Standard", "Enhanced", "Ultra Secure", "Memorable", "PIN"]
        algo_menu = ctk.CTkOptionMenu(
            algo_frame,
            variable=self.algorithm_var,
            values=algorithms,
            command=self.preview_password
        )
        algo_menu.pack(side="right")
        
        # Generate button
        ctk.CTkButton(
            content_frame,
            text="Generate Password",
            command=self.generate_and_display,
            height=40
        ).pack(pady=20)
        
        # Preview label
        self.preview_label = ctk.CTkLabel(
            content_frame,
            text="Password Preview: (Enter details and select algorithm)",
            font=("Roboto", 12),
            wraplength=500
        )
        self.preview_label.pack(pady=10)
        
        # Result display
        self.result_text = ctk.CTkTextbox(
            content_frame,
            height=100,
            width=600,
            font=("Roboto", 14)
        )
        self.result_text.pack(pady=20)
        
        # Password strength meter
        self.strength_label = ctk.CTkLabel(
            content_frame,
            text="Password Strength: N/A",
            font=("Roboto", 12)
        )
        self.strength_label.pack(pady=10)
        
        # Status bar
        self.status_bar = ctk.CTkLabel(
            self.root,
            text="Ready",
            font=("Roboto", 12)
        )
        self.status_bar.pack(pady=10)
        
    def create_input_field(self, parent, label, variable):
        frame = ctk.CTkFrame(parent)
        frame.pack(pady=10, fill="x", padx=20)
        
        ctk.CTkLabel(
            frame,
            text=label,
            font=("Roboto", 12)
        ).pack(side="left")
        
        entry = ctk.CTkEntry(
            frame,
            textvariable=variable,
            width=300
        )
        entry.pack(side="right")
        entry.bind('<KeyRelease>', lambda e: self.preview_password())

    def get_user_input(self):
        try:
            name = self.name_var.get().strip()
            if not name:
                raise ValueError("Name cannot be empty")
                
            age = int(self.age_var.get())
            if age <= 0 or age > 150:
                raise ValueError("Please enter a valid age")
                
            website = self.website_var.get().strip()
            phrases = [p.strip() for p in self.phrases_var.get().split(",") if p.strip()]
            max_length = self.max_length_var.get().strip()
            
            return name, age, website, phrases, max_length
            
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            return None

    def generate_salt(self):
        return secrets.token_hex(16)

    def secure_hash(self, input_str, salt):
        return hashlib.sha256((input_str + salt).encode()).hexdigest()

    def standard_algorithm(self, name, age, website, phrases, max_length):
        salt = self.generate_salt()
        base_hash = self.secure_hash(f"{name}{age}{website}", salt)
        
        # Mix in phrases
        for phrase in phrases:
            base_hash = self.secure_hash(base_hash + phrase, salt)
            
        # Add special characters and numbers
        password = list(base_hash[:16])  # Take first 16 chars
        password.extend(random.choice(string.punctuation) for _ in range(2))
        password.extend(str(random.randint(0, 9)) for _ in range(2))
        
        random.shuffle(password)
        result = ''.join(password)
        
        if max_length and max_length.isdigit():
            result = result[:int(max_length)]
            
        return result

    def enhanced_algorithm(self, name, age, website, phrases, max_length):
        # Use more entropy sources
        entropy = secrets.token_bytes(32)
        base = hashlib.blake2b(entropy).hexdigest()
        
        # Mix user inputs
        components = [name, str(age), website] + phrases
        for comp in components:
            entropy = secrets.token_bytes(16)
            base = hashlib.blake2b(
                (base + comp).encode(),
                key=entropy
            ).hexdigest()
        
        # Ensure password complexity
        password = []
        password.extend(random.choice(string.ascii_uppercase) for _ in range(2))
        password.extend(random.choice(string.ascii_lowercase) for _ in range(2))
        password.extend(random.choice(string.digits) for _ in range(2))
        password.extend(random.choice(string.punctuation) for _ in range(2))
        password.extend(base[:8])  # Add 8 chars from hash
        
        random.shuffle(password)
        result = ''.join(password)
        
        if max_length and max_length.isdigit():
            result = result[:int(max_length)]
            
        return result

    def ultra_secure_algorithm(self, name, age, website, phrases, max_length):
        # Multiple rounds of hashing with different algorithms
        data = f"{name}{age}{website}{''.join(phrases)}"
        
        hash1 = hashlib.sha512(data.encode()).hexdigest()
        hash2 = hashlib.blake2b(hash1.encode()).hexdigest()
        hash3 = hashlib.sha3_512(hash2.encode()).hexdigest()
        
        # Create complex password
        password = []
        password.extend(random.choice(string.ascii_letters) for _ in range(4))
        password.extend(random.choice(string.digits) for _ in range(4))
        password.extend(random.choice(string.punctuation) for _ in range(4))
        password.extend(hash3[:8])  # Add 8 chars from final hash
        
        # Additional entropy
        password.extend(secrets.token_urlsafe(4))
        
        random.shuffle(password)
        result = ''.join(password)
        
        if max_length and max_length.isdigit():
            result = result[:int(max_length)]
            
        return result

    def memorable_algorithm(self, name, age, website, phrases, max_length):
        # Create memorable password using user inputs
        components = []
        
        # Use first 3 letters of name
        components.append(name[:3].capitalize())
        
        # Add age backwards
        components.append(str(age)[::-1])
        
        # Add first letter of each phrase
        phrase_chars = ''.join(p[0].upper() for p in phrases if p)
        components.append(phrase_chars)
        
        # Add special chars between components
        special_chars = ['@', '#', '$', '&']
        password = random.choice(special_chars).join(components)
        
        # Add random number
        password += str(random.randint(100, 999))
        
        if max_length and max_length.isdigit():
            password = password[:int(max_length)]
            
        return password

    def pin_algorithm(self, name, age, website, phrases, max_length):
        # Generate a PIN-style password
        # Hash inputs to get a seed
        seed = hashlib.sha256(f"{name}{age}{website}".encode()).hexdigest()
        random.seed(int(seed, 16))
        
        # Generate 8-digit PIN
        pin = ''.join(str(random.randint(0, 9)) for _ in range(8))
        
        if max_length and max_length.isdigit():
            pin = pin[:int(max_length)]
            
        return pin

    def calculate_password_strength(self, password):
        score = 0
        
        # Length
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
            
        # Character types
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in string.punctuation for c in password):
            score += 1
            
        # Return strength label
        if score >= 5:
            return "Very Strong"
        elif score >= 4:
            return "Strong"
        elif score >= 3:
            return "Moderate"
        else:
            return "Weak"

    def preview_password(self, *args):
        inputs = self.get_user_input()
        if not inputs:
            self.preview_label.configure(text="Preview: (Invalid inputs)")
            return
            
        name, age, website, phrases, max_length = inputs
        
        try:
            # Generate short preview
            algorithm = self.algorithm_var.get()
            preview = self.generate_password()[:12] + "..."
            self.preview_label.configure(text=f"Preview ({algorithm}): {preview}")
        except Exception:
            self.preview_label.configure(text="Preview: (Enter valid inputs)")

    def generate_password(self):
        inputs = self.get_user_input()
        if not inputs:
            return None
            
        name, age, website, phrases, max_length = inputs
        algorithm = self.algorithm_var.get()
        
        algorithms = {
            "Standard": self.standard_algorithm,
            "Enhanced": self.enhanced_algorithm,
            "Ultra Secure": self.ultra_secure_algorithm,
            "Memorable": self.memorable_algorithm,
            "PIN": self.pin_algorithm
        }
        
        return algorithms[algorithm](name, age, website, phrases, max_length)

    def generate_and_display(self):
        self.status_bar.configure(text="Generating password...")
        self.result_text.delete("1.0", tk.END)
        
        password = self.generate_password()
        if password:
            strength = self.calculate_password_strength(password)
            self.result_text.insert("1.0", f"Generated Password:\n{password}\n\n")
            self.result_text.insert("end", f"Length: {len(password)} characters\n")
            self.result_text.insert("end", f"Algorithm: {self.algorithm_var.get()}")
            self.strength_label.configure(text=f"Password Strength: {strength}")
            self.status_bar.configure(text="Password generated successfully!")
        else:
            self.status_bar.configure(text="Failed to generate password")
            self.strength_label.configure(text="Password Strength: N/A")

if __name__ == "__main__":
    app = PasswordGeneratorUI()
    app.root.mainloop()
