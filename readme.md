# P2P Chat with Encryption

This is a Python-based peer-to-peer (P2P) chat application that allows secure communication between users over TCP, utilizing RSA encryption for message security. The application has a graphical user interface (GUI) built using Tkinter, which provides a simple and intuitive way to send encrypted messages to contacts.

## Features

- **Secure Communication:** All messages are encrypted using RSA encryption with OAEP padding.
- **Peer-to-Peer Connections:** Users can connect to each other using TCP protocol.
- **Connection Tokens:** Use base64-encoded tokens to securely share connection details between peers.
- **GUI Interface:** A simple Tkinter-based GUI to manage connections, send/receive messages, and view chat history.
- **Public/Private Key Pair Generation:** The application generates a unique RSA key pair for each user for secure communication.
- **Contact Management:** Users can add contacts via connection tokens, and manage their chat history.

## Requirements

- Python 3.x
- Required libraries:
  - `cryptography` (for RSA encryption and key management)
  - `requests` (to fetch public IP)
  - `tkinter` (for GUI)

You can install the required libraries with pip:

```bash
pip install cryptography requests
```

## Usage

1. **Run the Application:**
   Simply run the `chat.py` script to start the application. The script will:
   - Ask for a username.
   - Start a local TCP server.
   - Generate a unique connection token.
   - Open the GUI for managing contacts and sending messages.

2. **Connection Process:**
   - After starting the application, you will get a unique connection token.
   - To connect with another user, provide their connection token.
   - Once connected, you can send encrypted messages securely to the contact.

3. **Message Encryption:**
   All messages sent between users are encrypted using RSA and the OAEP padding scheme. This ensures the confidentiality of the communication.

4. **Managing Contacts:**
   - Add contacts by sharing your connection token.
   - Once a contact requests to connect, you can accept or deny the connection request.

## How It Works

- **Local and Public IP:** The application fetches your local IP and public IP to help set up connections.
- **TCP Server:** A server listens for incoming connections and handles client requests.
- **RSA Encryption:** Messages are encrypted with the recipient's public key and decrypted using the recipient's private key.
- **GUI Updates:** The application continuously updates the contact list and message history based on incoming messages.

## Example

- **Starting the Application:**
  ```bash
  python chat.py
  ```
- **GUI:**
  - Enter your username when prompted.
  - Your connection ID will be displayed, which you can share with others.
  - Add contacts by entering their connection token.
  - Select a contact from the list to chat.

## Code Breakdown

- **RSA Key Management:** Keys are generated using the `cryptography` library. Each user has a public/private key pair for encrypting and decrypting messages.
- **TCP Server:** A TCP server listens on a random port and handles incoming connection requests from other users.
- **Message Queue:** Messages are added to a queue and displayed in the GUI.
- **Background Tasks:** Background threads handle connections, message decryption, and GUI updates.

## Contributing

Feel free to fork the repository and submit pull requests for any improvements or bug fixes.

## License

This project is open-source and available under the MIT License. See `LICENSE` for more information.

---

## Files

- `chat.py`: Main script containing the P2P chat application logic.
- `requirements.txt`: List of Python libraries required for the application.