import socket

def start_http_server():
    # Host on localhost, port 8080 (standard HTTP is 80, but 8080 doesn't require admin privileges)
    HOST = ''
    PORT = <your port> # 2000 => 65535

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Allow reusing the address to avoid "Address already in use" errors
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"[HTTP SERVER] Running on http://{HOST}:{PORT} ...")

        while True:
            # Wait for a browser/client to connect
            conn, addr = server_socket.accept()
            with conn:
                # Read the incoming HTTP request from the client
                request = conn.recv(1024).decode('utf-8')
                
                # Print the request header (optional, just to see what the browser sends)
                print(f"\n[RECEIVED REQUEST FROM {addr}]:")
                print(request.split('\r\n')[0]) # Prints just the first line (e.g., GET / HTTP/1.1)

                # Construct a valid HTTP raw response
                # 1. Status Line
                # 2. Headers (Content-Type and Content-Length tell the browser what it's receiving)
                # 3. Blank Line (\r\n\r\n) - CRITICAL to separate headers from body
                # 4. Response Body (The actual HTML/text content)
                html_body = "<h1>Hello, World!</h1>\n<p>Sent directly from a raw Python socket.</p>"
                
                http_response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(html_body.encode('utf-8'))}\r\n"
                    "Connection: close\r\n"
                    "\r\n"  # This blank line is required by the HTTP protocol
                    f"{html_body}"
                )

                # Send the response back to the client
                conn.sendall(http_response.encode('utf-8'))

if __name__ == "__main__":
    start_http_server()
