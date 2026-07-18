import socket

def start_server():
    # Define the server host and port
    # '127.0.0.1' means localhost (your own machine)
    HOST = '127.0.0.1'
    PORT = 7777       

    # Create a socket object
    # AF_INET = IPv4, SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Bind the socket to the host and port
        server_socket.bind((HOST, PORT))
        
        # Listen for incoming connections
        server_socket.listen()
        print(f"[SERVER] Listening on {HOST}:{PORT}...")

        # Wait for a connection
        conn, addr = server_socket.accept()
        with conn:
            print(f"[SERVER] Connected securely by {addr}")
            
            # Receive data from the client (buffer size of 1024 bytes)
            data = conn.recv(1024)
            if data:
                # Decode the bytes into a string
                message = data.decode('utf-8')
                print(f"[SERVER] Received message: '{message}'")
                
                # Send a response back to the client
                response = "Message received loud and clear!"
                conn.sendall(response.encode('utf-8'))
                print("[SERVER] Response sent. Closing connection.")

if __name__ == "__main__":
    start_server()
