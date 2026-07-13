import socket
import struct
import os

# SHARED RDT PROTOCOL DEFINITIONS
HEADER_FORMAT = '!IIBH'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

FLAG_SYN  = 0x01
FLAG_ACK  = 0x02
FLAG_DATA = 0x04
FLAG_FIN  = 0x08

def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += b'\0'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + (data[i+1])
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)
    return (~checksum) & 0xffff

class HybridFTPClient:
    def __init__(self, host, port=2121):
        self.host = host
        self.control_port = port
        self.control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Data Channel properties
        self.data_sock = None
        self.data_ip = None
        self.data_port = None

    def connect(self):
        """Establish the TCP Control Channel."""
        self.control_sock.connect((self.host, self.control_port))
        print(self.get_response())

    def send_command(self, cmd):
        """Send a standard FTP command over TCP and return the response."""
        self.control_sock.sendall((cmd + "\r\n").encode('utf-8'))
        return self.get_response()

    def get_response(self):
        """Read the TCP response."""
        return self.control_sock.recv(1024).decode('utf-8').strip()

    def enter_passive_mode(self):
        """Send PASV command and parse the resulting IP and Port for the UDP Data Channel."""
        response = self.send_command("PASV")
        print(f"[Server] {response}")
        if response.startswith("227"):
            # Extract the (h1,h2,h3,h4,p1,p2) part
            start = response.find('(') + 1
            end = response.find(')')
            parts = response[start:end].split(',')
            self.data_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}"
            self.data_port = (int(parts[4]) * 256) + int(parts[5])
            # Setup the UDP Data Socket
            self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.data_sock.settimeout(5.0)
            return True
        return False
    
    def rdt_download(self, local_filename):
        """Receive file chunks over UDP using Stop-and-Wait."""
        if not self.data_sock:
            print("[-] Data connection not established. Run PASV first.")
            return
        expected_seq = 1
        print(f"[*] Downloading to {local_filename} over UDP...")
        try:
            with open(local_filename, 'wb') as f:
                while True:
                    try:
                        packet, addr = self.data_sock.recvfrom(2048)
                        if len(packet) < HEADER_SIZE:
                            continue
                        header_bytes = packet[:HEADER_SIZE]
                        payload = packet[HEADER_SIZE:]
                        r_seq, r_ack, r_flags, r_chksum = struct.unpack(HEADER_FORMAT, header_bytes)
                        # Checksum verification
                        temp_header = struct.pack(HEADER_FORMAT, r_seq, r_ack, r_flags, 0)
                        if calculate_checksum(temp_header + payload) != r_chksum:
                            print(f"[!] Corrupted packet Seq={r_seq}. Dropping.")
                            continue
                        # In-order packet processing
                        if r_seq == expected_seq:
                            f.write(payload)                            
                            # Send ACK
                            ack_header = struct.pack(HEADER_FORMAT, 0, expected_seq, FLAG_ACK, 0)
                            ack_chksum = calculate_checksum(ack_header)
                            final_ack = struct.pack(HEADER_FORMAT, 0, expected_seq, FLAG_ACK, ack_chksum)
                            self.data_sock.sendto(final_ack, addr)
                            if r_flags & FLAG_FIN:
                                print(f"[+] Download complete: {local_filename}")
                                break
                            expected_seq += 1
                        # Handle duplicated/delayed packets
                        elif r_seq < expected_seq:
                            ack_header = struct.pack(HEADER_FORMAT, 0, r_seq, FLAG_ACK, 0)
                            ack_chksum = calculate_checksum(ack_header)
                            final_ack = struct.pack(HEADER_FORMAT, 0, r_seq, FLAG_ACK, ack_chksum)
                            self.data_sock.sendto(final_ack, addr)
                    except socket.timeout:
                        print("[-] UDP Timeout waiting for server data.")
                        break
        finally:
            self.data_sock.close()
            self.data_sock = None

def main():
    client = HybridFTPClient('127.0.0.1')
    try:
        client.connect()
    except ConnectionRefusedError:
        print("[-] Connection failed. Check the server again!")
        return
    while True:
        cmd_input = input("ftp> ").strip()
        if not cmd_input:
            continue
        parts = cmd_input.split(' ', 1)
        command = parts[0].upper()
        if command == "QUIT":
            print(client.send_command(cmd_input))
            break
        # Example macro: 'get filename' automatically handles PASV + RETR + UDP download
        elif command == "GET" and len(parts) > 1:
            filename = parts[1]
            if client.enter_passive_mode():
                print(f"[Server] {client.send_command(f'RETR {filename}')}")
                client.rdt_download(f"downloaded_{filename}")
        else:
            # Send standard commands directly to the control channel (USER, PASS, PWD, CWD, HASH)
            print(f"[Server] {client.send_command(cmd_input)}")

if __name__ == "__main__":
    main()
