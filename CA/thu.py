import tkinter as tk
from tkinter import messagebox
import requests

# API URL
API_BASE_URL = "http://127.0.0.1:8000"  # Thay bằng URL của server Django

# Global variables to store logged-in user info and session cookies
current_user = None
session_cookies = None

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
    tk.Button(dashboard_window, text="Generate KeyPair", command=show_generate_keypair_window).pack(pady=10)

    # Expire KeyPair button
    tk.Button(dashboard_window, text="Expire KeyPair", command=show_expire_keypair_window).pack(pady=10)

    # Logout button
    tk.Button(dashboard_window, text="Logout", command=lambda: [dashboard_window.destroy(), logout()]).pack(pady=20)

# Giao diện Generate KeyPair
def show_generate_keypair_window():
    generate_window = tk.Toplevel(root)
    generate_window.title("Generate KeyPair")
    generate_window.geometry("400x300")

    tk.Label(generate_window, text="Verification Code:").pack(pady=5)
    verification_code_entry = tk.Entry(generate_window)
    verification_code_entry.pack(pady=5)

    tk.Label(generate_window, text="Algorithm:").pack(pady=5)
    algorithm_entry = tk.Entry(generate_window)
    algorithm_entry.pack(pady=5)

    tk.Label(generate_window, text="Bit Size:").pack(pady=5)
    bit_size_entry = tk.Entry(generate_window)
    bit_size_entry.pack(pady=5)

    def handle_generate_keypair():
        verification_code = verification_code_entry.get()
        algorithm = algorithm_entry.get()
        bit_size = bit_size_entry.get()

        url = f"{API_BASE_URL}/keypair/generate-keypair/"
        data = {
            "verification_code": verification_code,
            "algorithm": algorithm,
            "bit_size": bit_size
        }

        try:
            csrf_token = session_cookies.get('csrftoken')
            headers = {'X-CSRFToken': csrf_token} if csrf_token else {}

            response = requests.post(url, json=data, cookies=session_cookies, headers=headers)
            if response.status_code == 200:
                messagebox.showinfo("Success", "Key pair generated successfully!")
            else:
                messagebox.showerror("Error", response.json().get("error", "Unknown error"))
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Connection Error", str(e))

    tk.Button(generate_window, text="Generate", command=handle_generate_keypair).pack(pady=20)

# Giao diện Expire KeyPair
def show_expire_keypair_window():
    expire_window = tk.Toplevel(root)
    expire_window.title("Expire KeyPair")
    expire_window.geometry("400x300")

    tk.Label(expire_window, text="Verification Code:").pack(pady=5)
    verification_code_entry = tk.Entry(expire_window)
    verification_code_entry.pack(pady=5)

    def handle_expire_keypair():
        verification_code = verification_code_entry.get()

        url = f"{API_BASE_URL}/keypair/expire-keypair/"
        data = {"verification_code_expire": verification_code}

        try:
            csrf_token = session_cookies.get('csrftoken')
            headers = {'X-CSRFToken': csrf_token} if csrf_token else {}

            response = requests.post(url, json=data, cookies=session_cookies, headers=headers)
            if response.status_code == 200:
                messagebox.showinfo("Success", "Key pair expired successfully!")
            else:
                messagebox.showerror("Error", response.json().get("error", "Unknown error"))
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Connection Error", str(e))

    tk.Button(expire_window, text="Expire", command=handle_expire_keypair).pack(pady=20)

# Main application
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Login App")
    root.geometry("400x300")

    # Login button
    tk.Button(root, text="Login", command=show_login_window).pack(pady=20)

    # Run the application
    root.mainloop()
