# Python app with a GUI to connect to MySQL database and fetch data from a table

import tkinter as tk
from tkinter import ttk, messagebox
from mysql.connector import connection

def connect_to_mysql():
    dict = {
        'user': 'root',
        'password': '1234',
        'host': 'localhost',
        'database': 'web'
    }

    try:
        # Connecting to the server
        conn = connection.MySQLConnection(**dict)
        print("Connection successful")
        return conn
    except Exception as e:
        print("Error while connecting to MySQL:", e)
        messagebox.showerror("Connection Error", f"Error while connecting to MySQL:\n{e}")
        return None

def disconnect_from_mysql(conn):
    if conn is not None and conn.is_connected():
        conn.close()
        print("Disconnected from MySQL")

def fetch_data_from_table(conn, table_name):
    try:
        # Creating a cursor
        cursor = conn.cursor()
        # Query to fetch data
        query = f"SELECT * FROM web.users_userprofile;"
        cursor.execute(query)
        # Fetch all rows
        rows = cursor.fetchall()
        cursor.close()
        return rows
    except Exception as e:
        print(f"Error fetching data from table '{table_name}':", e)
        messagebox.showerror("Query Error", f"Error fetching data from table '{table_name}':\n{e}")
        return []

def display_data():
    table_name = table_name_entry.get()
    if not table_name:
        messagebox.showwarning("Input Error", "Please enter a table name.")
        return

    conn = connect_to_mysql()
    if conn:
        rows = fetch_data_from_table(conn, table_name)
        for row in tree.get_children():
            tree.delete(row)
        
        for row in rows:
            tree.insert("", tk.END, values=row)

        disconnect_from_mysql(conn)

# GUI setup
root = tk.Tk()
root.title("MySQL Table Viewer")
root.geometry("800x600")

frame = tk.Frame(root)
frame.pack(pady=20)

# Input for table name
table_name_label = tk.Label(frame, text="Table Name:")
table_name_label.grid(row=0, column=0, padx=5)

table_name_entry = tk.Entry(frame)
table_name_entry.grid(row=0, column=1, padx=5)

fetch_button = tk.Button(frame, text="Fetch Data", command=display_data)
fetch_button.grid(row=0, column=2, padx=5)

# Treeview for displaying data
columns = ("Column1", "Column2", "Column3", "Column4")  # Replace with actual column names

scroll_x = tk.Scrollbar(root, orient=tk.HORIZONTAL)
scroll_y = tk.Scrollbar(root, orient=tk.VERTICAL)

tree = ttk.Treeview(root, columns=columns, show="headings", xscrollcommand=scroll_x.set, yscrollcommand=scroll_y.set)

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)

scroll_x.config(command=tree.xview)
scroll_y.config(command=tree.yview)

scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
tree.pack(fill=tk.BOTH, expand=True)

# Run the application
root.mainloop()