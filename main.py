import socket
import random
import json
import queue
import threading
import base64
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import requests

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        public_ip = response.json().get('ip')
        return public_ip
    except Exception as e:
        print(f"Error getting public IP: {e}")
        return "127.0.0.1"  # fallback to localhost

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"  # fallback to localhost if unable to get IP
    finally:
        s.close()
    return local_ip


def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)

def generate_connection_token(username, ip, port, protocol):
    connection_info = {"username": username, "ip": ip, "port": port, "protocol": protocol}
    token = base64.urlsafe_b64encode(json.dumps(connection_info).encode()).decode()
    return token


def decode_connection_token(token):
    try:
        connection_info = json.loads(base64.urlsafe_b64decode(token.encode()).decode())
        return connection_info["username"], connection_info["ip"], connection_info["port"], connection_info["protocol"]
    except Exception:
        return None, None, None, None

def encrypt_message(message, public_key):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_message(encrypted_message, private_key):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    return decrypted

def tcp_server(host, port, connection_requests):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"Server listening on {host}:{port}")
        while True:
            client_socket, client_address = server_socket.accept()
            threading.Thread(target=handle_tcp_client, args=(client_socket, connection_requests)).start()
    except OSError as e:
        print(f"Error binding server socket: {e}")

def handle_tcp_client(client_socket, connection_requests):
    try:
        request = client_socket.recv(4096)
        data = json.loads(request.decode())
        if data["type"] == "connection_request":
            peer_username = data["username"]
            peer_ip = data["ip"]
            peer_port = data["port"]
            peer_public_key = deserialize_public_key(data["public_key"].encode())  
            response = json.dumps({
                "type": "connection_response",
                "username": username,
                "status": "successful",
                "public_key": serialize_public_key(public_key).decode() 
            })
            client_socket.send(response.encode())
            connection_requests.put((peer_username, peer_ip, peer_port, peer_public_key, client_socket))
        elif data["type"] == "message":
            sender = data["from"]
            encrypted_message = base64.b64decode(data["message"])
            decrypted_message = decrypt_message(encrypted_message, private_key)
            message_queue.put((sender, decrypted_message))
    except Exception:
        client_socket.close()


def send_connection_response(client_socket, username, status):
    try:
        response = json.dumps({"type": "connection_response", "username": username, "status": status})
        client_socket.send(response.encode())
        client_socket.close()
    except Exception:
        pass

def start_gui():
    global message_queue, connection_requests, contacts, message_history, current_contact, private_key, public_key
    current_contact = None
    private_key, public_key = generate_rsa_keys()
    root = tk.Tk()
    root.title("P2P Chat with Encryption")
    tk.Label(root, text="Your Connection ID:", font=("Arial", 10, "bold")).grid(row=0, column=0, padx=5, pady=5, sticky="w")
    connection_id_box = tk.Text(root, height=2, width=60, wrap=tk.WORD)
    connection_id_box.insert(tk.END, connection_token)
    connection_id_box.configure(state=tk.DISABLED)
    connection_id_box.grid(row=0, column=1, columnspan=2, padx=5, pady=5)
    connection_id_box.bind("<Button-1>", lambda event: connection_id_box.configure(state=tk.NORMAL))
    connection_id_box.bind("<FocusOut>", lambda event: connection_id_box.configure(state=tk.DISABLED))
    tk.Label(root, text="Add Person:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
    token_entry = tk.Entry(root, width=40)
    token_entry.grid(row=1, column=1, padx=5, pady=5)

    def add_connection():
        token = token_entry.get().strip()
        if not token:
            return
        peer_username, peer_ip, peer_port, peer_protocol = decode_connection_token(token)
        if peer_username and peer_ip and peer_port and peer_protocol:
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((peer_ip, peer_port))
                public_key_bytes = serialize_public_key(public_key).decode()
                request = json.dumps({
                    "type": "connection_request",
                    "username": username,
                    "ip": host,
                    "port": port,
                    "public_key": public_key_bytes 
                })
                client_socket.send(request.encode())
                response = json.loads(client_socket.recv(1024).decode())
                if response["status"] == "successful":
                    peer_public_key = deserialize_public_key(response["public_key"].encode())
                    contacts[peer_username] = {
                        "ip": peer_ip,
                        "port": peer_port,
                        "protocol": peer_protocol,
                        "public_key": peer_public_key  
                    }
                    message_history[peer_username] = []
                    update_contacts_list()
                    append_message(f"Connected to {peer_username}.", "System")
                else:
                    append_message(f"Connection denied by {peer_username}.", "System")
                client_socket.close()
            except Exception as e:
                append_message(f"Error connecting to {peer_username}: {e}", "System")
        else:
            messagebox.showerror("Error", "Invalid connection token.")
        token_entry.delete(0, tk.END)
    tk.Button(root, text="Add", command=add_connection).grid(row=1, column=2, padx=5, pady=5)
    tk.Label(root, text="Contacts:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
    contacts_listbox = tk.Listbox(root, height=10, width=20)
    contacts_listbox.grid(row=3, column=0, padx=5, pady=5, sticky="ns")

    def update_contacts_list():
        contacts_listbox.delete(0, tk.END)
        for contact in contacts:
            contacts_listbox.insert(tk.END, contact)

    def select_contact(event):
        global current_contact
        selected_contact = contacts_listbox.get(tk.ACTIVE)
        if selected_contact:
            current_contact = selected_contact
            update_chat_display()

    contacts_listbox.bind("<<ListboxSelect>>", select_contact)
    chat_display = scrolledtext.ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED, height=20, width=50)
    chat_display.grid(row=3, column=1, columnspan=2, padx=5, pady=5)

    def update_chat_display():
        chat_display.configure(state=tk.NORMAL)
        chat_display.delete(1.0, tk.END)
        if current_contact in message_history:
            for message in message_history[current_contact]:
                chat_display.insert(tk.END, message + "\n")
        chat_display.configure(state=tk.DISABLED)

    message_entry = tk.Entry(root, width=40)
    message_entry.grid(row=4, column=1, padx=5, pady=5)

    def send_message():
        if not current_contact:
            messagebox.showerror("Error", "No contact selected.")
            return
        if current_contact not in contacts:
            messagebox.showerror("Error", "Contact not found.")
            return
        peer_ip, peer_port = contacts[current_contact]["ip"], contacts[current_contact]["port"]
        peer_public_key = contacts[current_contact].get("public_key")
        if not peer_public_key:
            messagebox.showerror("Error", "Public key for this contact is not available.")
            return
        message = message_entry.get().strip()
        if message:
            try:
                encrypted_message = encrypt_message(message, peer_public_key)
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((peer_ip, peer_port))
                client_socket.send(json.dumps({
                    "type": "message",
                    "message": base64.b64encode(encrypted_message).decode(),
                    "from": username
                }).encode())
                client_socket.close()
                append_message(f"You: {message}", current_contact)
                message_entry.delete(0, tk.END)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to send message: {e}")

    tk.Button(root, text="Send", command=send_message).grid(row=4, column=2, padx=5, pady=5)

    def append_message(message, contact):
        if contact in message_history:
            message_history[contact].append(message)
            if current_contact == contact:
                update_chat_display()

    def handle_requests():
        while not connection_requests.empty():
            peer_username, peer_ip, peer_port, peer_public_key, client_socket = connection_requests.get()
            accept = messagebox.askyesno("Connection Request", f"{peer_username} wants to connect. Accept?")
            if accept:
                contacts[peer_username] = {
                    "ip": peer_ip,
                    "port": peer_port,
                    "protocol": "TCP",
                    "public_key": peer_public_key  
                }
                message_history[peer_username] = []
                update_contacts_list()
                send_connection_response(client_socket, username, "successful")
                append_message(f"Connected to {peer_username}.", "System")
            else:
                send_connection_response(client_socket, username, "denied")
                append_message(f"Denied connection to {peer_username}.", "System")


    def process_background_tasks():
        while True:
            if not message_queue.empty():
                sender, message = message_queue.get()
                append_message(f"{sender}: {message}", sender)
            handle_requests()
            root.update_idletasks()
            root.update()

    threading.Thread(target=process_background_tasks, daemon=True).start()
    root.mainloop()

def chat():
    global message_queue, connection_requests, contacts, message_history, username, host, port, connection_token
    host = get_local_ip()

    port = random.randint(10000, 20000)
    message_queue = queue.Queue()
    connection_requests = queue.Queue()
    contacts = {}
    message_history = {}
    root = tk.Tk()
    root.withdraw()
    username = simpledialog.askstring("Username", "Enter your username:", parent=root)
    root.destroy()
    if not username:
        print("Username is required. Exiting.")
        return
    connection_token = generate_connection_token(username, host, port, "TCP")
    threading.Thread(target=tcp_server, args=(host, port, connection_requests), daemon=True).start()
    start_gui()

if __name__ == "__main__":
    chat()