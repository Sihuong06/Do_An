import tkinter as tk
from tkinter import messagebox
import requests
from PyQt5.QtWidgets import QApplication, QVBoxLayout, QFormLayout, QLineEdit, QComboBox, QPushButton, QWidget,QFileDialog, QMessageBox
from PyQt5.QtCore import Qt
# API URL
API_BASE_URL = "http://127.0.0.1:8000"  # Thay bằng URL của server Django

# Global variables to store logged-in user info and session cookies
current_user = None
session_cookies = None

class KeyPairApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Generate and Expire Key Pair")

        # Main layout
        layout = QVBoxLayout()

        # Verification code input
        form_layout = QFormLayout()
        self.verification_code_input = QLineEdit()
        self.verification_code_input.setPlaceholderText("Enter Verification Code")
        form_layout.addRow("Verification Code:", self.verification_code_input)

        # Algorithm selection
        self.algorithm_select = QComboBox()
        self.algorithm_select.addItems(["RSA", "DSA", "ECDSA"])
        self.algorithm_select.currentIndexChanged.connect(self.update_bit_size_options)
        form_layout.addRow("Algorithm:", self.algorithm_select)

        # Bit size selection
        self.bit_size_select = QComboBox()
        self.update_bit_size_options()  # Initialize with default algorithm options
        form_layout.addRow("Bit Size:", self.bit_size_select)

        # Submit button
        self.submit_button = QPushButton("Generate Key Pair")
        self.submit_button.clicked.connect(self.generate_keypair)

        # Add widgets to layout
        layout.addLayout(form_layout)
        layout.addWidget(self.submit_button, alignment=Qt.AlignCenter)

        self.setLayout(layout)

    def update_bit_size_options(self):
        algorithm = self.algorithm_select.currentText()
        self.bit_size_select.clear()

        if algorithm in ["RSA", "DSA"]:
            self.bit_size_select.addItems(["1024", "2048", "3072", "4096"])
        elif algorithm == "ECDSA":
            self.bit_size_select.addItems(["256", "384", "521"])



    def generate_keypair(self):
        # Get input values
        verification_code = self.verification_code_input.text()
        algorithm = self.algorithm_select.currentText()
        bit_size = self.bit_size_select.currentText()

        # Send these values to the backend API
        url = "http://127.0.0.1:8000/keypair/generate-keypair/"
        data = {
            "verification_code": verification_code,
            "algorithm": algorithm,
            "bit_size": bit_size
        }

        try:
            response = requests.post(url, json=data)
            response.raise_for_status()  # Raise an error for HTTP errors

            # Parse response data
            result = response.json()
            private_key = result.get("private_key")
            if private_key:
                # Save the private key to a file
                save_path, _ = QFileDialog.getSaveFileName(
                    self, 
                    "Save Private Key", 
                    f"private_key_{algorithm}.pem", 
                    "PEM Files (*.pem)"
                )
                if save_path:
                    with open(save_path, "w") as file:
                        file.write(private_key)
                    QMessageBox.information(self, "Success", "Key pair generated and private key saved successfully!")
                else:
                    QMessageBox.warning(self, "Cancelled", "Save operation cancelled.")
            else:
                QMessageBox.critical(self, "Error", "Failed to get private key from server response.")

        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

# Hàm đăng nhập
def login(username, password):
    global current_user, session_cookies
    url = f"{API_BASE_URL}/users/api/login/"
    data = {"username": username, "password": password}
    try:
        response = requests.post(url, json=data)
        if response.status_code == 200:
            current_user = response.json()  # Store user info
            session_cookies = response.cookies  # Lưu cookies session
            messagebox.showinfo("Login Successful", f"Welcome {current_user['username']}!")
            return True
        else:
            error = response.json().get("error", "Unknown error")
            messagebox.showerror("Login Failed", error)
            return False
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Connection Error", str(e))
        return False

# Hàm đăng xuất
def logout():
    global current_user, session_cookies
    url = f"{API_BASE_URL}/users/api/logout/"
    try:
        response = requests.get(url, cookies=session_cookies)
        if response.status_code == 200:
            current_user = None
            session_cookies = None
            messagebox.showinfo("Logout Successful", "You have been logged out.")
        else:
            messagebox.showerror("Logout Failed", "Unable to log out.")
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Connection Error", str(e))

# Giao diện đăng nhập
def show_login_window():
    login_window = tk.Toplevel(root)
    login_window.title("Login")
    login_window.geometry("300x200")

    # Username label and entry
    tk.Label(login_window, text="Username:").pack(pady=5)
    username_entry = tk.Entry(login_window)
    username_entry.pack(pady=5)

    # Password label and entry
    tk.Label(login_window, text="Password:").pack(pady=5)
    password_entry = tk.Entry(login_window, show="*")
    password_entry.pack(pady=5)

    # Hàm xử lý đăng nhập
    def handle_login():
        username = username_entry.get()
        password = password_entry.get()
        if login(username, password):
            login_window.destroy()
            show_dashboard()  # Show dashboard after successful login

    # Login button
    tk.Button(login_window, text="Login", command=handle_login).pack(pady=20)

# Giao diện dashboard
def show_dashboard():
    dashboard_window = tk.Toplevel(root)
    dashboard_window.title("Dashboard")
    dashboard_window.geometry("400x300")

    tk.Label(dashboard_window, text=f"Welcome, {current_user['username']}!", font=("Arial", 14)).pack(pady=10)

    # Generate KeyPair button
    tk.Button(dashboard_window, text="Generate KeyPair", command=show_generate()).pack(pady=10)

    # Expire KeyPair button
    # Logout button
    tk.Button(dashboard_window, text="Logout", command=lambda: [dashboard_window.destroy(), logout()]).pack(pady=20)
def show_generate():
    window = KeyPairApp()
    window.show()

# Main application
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Login App")
    root.geometry("400x300")

    # Login button
    tk.Button(root, text="Login", command=show_login_window).pack(pady=20)

    # Run the application
    root.mainloop()
