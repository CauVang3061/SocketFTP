import socket

def start_client():
    HOST = '152.42.203.221'  # The server's hostname or IP address
    PORT = 7777        # The port used by the server

    # Create a socket object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        print(f"[CLIENT] Connecting to server at {HOST}:{PORT}...")
        # Connect to the server
        client_socket.connect((HOST, PORT))
        
        # Define the message to send
        chat_message = "Hello Server! This is a chat message from the client."
        
        # Send the message (must be encoded to bytes)
        print(f"[CLIENT] Sending: '{chat_message}'")
        client_socket.sendall(chat_message.encode('utf-8'))
        
        # Look for the response
        data = client_socket.recv(1024)
        print(f"[CLIENT] Received from server: '{data.decode('utf-8')}'")

if __name__ == "__main__":
    start_client()
