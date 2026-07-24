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
            syn_header = struct.pack(HEADER_FORMAT, 0, 0, FLAG_SYN, 0)
            chksum = calculate_checksum(syn_header)
            final_syn = struct.pack(HEADER_FORMAT, 0, 0, FLAG_SYN, chksum)
            self.data_sock.sendto(final_syn, (self.data_ip, self.data_port))
            return True
        return False
    
    def rdt_download(self, local_filename):
        """Receive file chunks over UDP using Stop-and-Wait."""
        if not self.data_sock:
            print("[-] Data connection not established. Run PASV first.")
            return
        expected_seq = 1
        success = False
        print(f"[*] Downloading to {local_filename} over UDP...")
        try:
            with open(local_filename, 'wb') as f:
                while True:
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
                            success = True
                            break
                        expected_seq += 1
                    # Handle duplicated/delayed packets
                    elif r_seq < expected_seq:
                        ack_header = struct.pack(HEADER_FORMAT, 0, r_seq, FLAG_ACK, 0)
                        ack_chksum = calculate_checksum(ack_header)
                        final_ack = struct.pack(HEADER_FORMAT, 0, r_seq, FLAG_ACK, ack_chksum)
                        self.data_sock.sendto(final_ack, addr)
        except KeyboardInterrupt:
            print("\n[*] Abort requested by user! Sending ABOR to server...")
            resp = self.send_command("ABOR")
            print(f"[Server] {resp}")
            success = False
        except socket.timeout:
            print("[-] UDP Timeout waiting for server data.")
            success = False
        finally:
            self.data_sock.close()
            self.data_sock = None
            # Nếu tải không thành công, xóa bỏ file rác để giải phóng hệ thống
            if not success and os.path.exists(local_filename):
                os.remove(local_filename)
                # Ẩn thông báo nếu nó chỉ là file tạm của lệnh LIST
                if local_filename != ".temp_list.txt":
                    print(f"[*] Finish emptying corrupted file: {local_filename}")
    
    def rdt_upload(self, local_filepath, is_active_mode=False):
        """Send file chunks over UDP using Stop-and-Wait."""
        if not self.data_sock:
            print("[-] Data connection not established. Run PASV first.")
            return False
        if not os.path.isfile(local_filepath):
            print(f"[-] Local file not found: {local_filepath}")
            return False
        chunk_size = 1024
        seq_num = 1
        timeout = 2.0
        self.data_sock.settimeout(timeout)
        if is_active_mode:
            print("[*] Active Mode: Waiting for Server to initiate UDP connection...")
            try:
                # Wait for the Server's SYN packet
                syn_data, server_addr = self.data_sock.recvfrom(1024)
                print(f"[+] Received UDP ping from Server: {server_addr}")
                # Reassign the target address to the Server's actual UDP port
                target_addr = server_addr
            except KeyboardInterrupt:
                print("\n[*] Abort requested by user! Sending ABOR to server...")
                resp = self.send_command("ABOR")
                print(f"[Server] {resp}")
            except socket.timeout:
                print("[-] Timeout waiting for Server UDP SYN.")
                self.data_sock.close()
                self.data_sock = None
                return False
        else:
            # Passive Mode: The client already knows where to send
            target_addr = (self.data_ip, self.data_port)

        print(f"[*] Uploading {local_filepath} over UDP...")
        try:
            with open(local_filepath, 'rb') as f:
                payload = f.read()
            total_bytes = len(payload)
            offset = 0
            while True:
                is_last_chunk = (offset + chunk_size) >= total_bytes
                flags = FLAG_DATA | FLAG_FIN if is_last_chunk else FLAG_DATA
                chunk = payload[offset:offset + chunk_size]
                # Đóng gói và tính Checksum
                header = struct.pack(HEADER_FORMAT, seq_num, 0, flags, 0)
                chksum = calculate_checksum(header + chunk)
                final_packet = struct.pack(HEADER_FORMAT, seq_num, 0, flags, chksum) + chunk
                max_retries = 3
                attempts = 0
                ack_received = False
                while attempts < max_retries and not ack_received:
                    try:
                        self.data_sock.sendto(final_packet, target_addr)
                        ack_data, _ = self.data_sock.recvfrom(1024)
                        if len(ack_data) >= HEADER_SIZE:
                            r_seq, r_ack, r_flags, r_chksum = struct.unpack(HEADER_FORMAT, ack_data[:HEADER_SIZE])
                            if (r_flags & FLAG_ACK) and r_ack == seq_num:
                                ack_received = True
                    except socket.timeout:
                        attempts += 1
                        print(f"[RDT] Timeout! Resending Seq={seq_num}, Attempt {attempts}/{max_retries}")
                if not ack_received:
                    print("[-] Max retries exceeded. Upload aborted.")
                    return False
                offset += chunk_size
                seq_num += 1
                if offset >= total_bytes:
                    break
            print("[+] Upload complete!")
            return True
        except KeyboardInterrupt:
            print("\n[*] Abort requested by user! Sending ABOR to server...")
            resp = self.send_command("ABOR")
            print(f"[Server] {resp}")
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
        if not hasattr(client, 'active_mode'):
            client.active_mode = False
        parts = cmd_input.split(' ', 1)
        command = parts[0].upper()
        if command == "QUIT":
            print(client.send_command(cmd_input))
            break
        # Example macro: 'get filename' automatically handles PASV + RETR + UDP download
        elif command == "GET" and len(parts) > 1:
            filename = parts[1]
            if client.enter_passive_mode():
                resp = client.send_command(f'RETR {filename}')
                print(f"[Server] {resp}")
                # Chỉ tải khi Server báo 150
                if resp.startswith("150"):
                    client.rdt_download(f"downloaded_{filename}")
                    print(f"[Server] {client.get_response()}")
                else:
                    print("[-] Download aborted by server!")
        elif command == "PUT" and len(parts) > 1:
            filename = parts[1]
            if not os.path.isfile(filename):
                print(f"[-] Local file not found: {filename}")
                continue
            if client.enter_passive_mode():
                # Server mở file chờ sẵn
                resp = client.send_command(f'STOR {filename}')
                print(f"[Server] {resp}")
                if resp.startswith("150"):
                    # Client bắt đầu băm file và đẩy qua luồng UDP
                    client.rdt_upload(filename)
                    print(f"[Server] {client.get_response()}")
                else:
                    print("[-] Upload aborted by server!")
        elif command == "RETR" and len(parts) > 1:
            filename = parts[1]
            # Send TCP command
            resp = client.send_command(cmd_input)
            print(f"[Server] {resp}")
            # If server agrees (150), activate the UDP listening loop!
            if resp.startswith("150"):
                client.rdt_download(f"downloaded_{filename}")
                # Get the final 226 Transfer complete message over TCP
                print(f"[Server] {client.get_response()}")
        elif command in ["STOR", "APPE"] and len(parts) > 1:
            filename = parts[1]
            if not os.path.isfile(filename):
                print(f"[-] Local file not found: {filename}")
                continue
            resp = client.send_command(cmd_input)
            print(f"[Server] {resp}")
            if resp.startswith("150"):
                client.rdt_upload(filename, is_active_mode=client.active_mode)
                print(f"[Server] {client.get_response()}")
        elif command == "STOU":
            # 1. Determine which local file the user wants to upload
            if len(parts) > 1:
                local_filename = parts[1]
            else:
                # If they just typed 'STOU', prompt them for the local file
                local_filename = input("Local file to upload: ").strip()
            if not os.path.isfile(local_filename):
                print(f"[-] Local file not found: {local_filename}")
                continue
            # 2. Send the STOU command to the Server over TCP
            # (We only send "STOU" because the server generates the remote filename)
            resp = client.send_command("STOU")
            print(f"[Server] {resp}")
            # 3. If Server approves (150), fire up the UDP Data Channel
            if resp.startswith("150"):
                client.rdt_upload(local_filename, is_active_mode=client.active_mode)
                # 4. Read the final 226 or 426 response over TCP
                print(f"[Server] {client.get_response()}")
        elif command in ["LIST", "NLST"]:
            if client.enter_passive_mode():
                resp = client.send_command(cmd_input)
                print(f"[Server] {resp}")
                if resp.startswith("150"):
                    # Kênh RDT tải danh sách về dưới dạng một file ẩn
                    client.rdt_download(".temp_list.txt")
                    print(f"[Server] {client.get_response()}")
                    try:
                        with open(".temp_list.txt", "r", encoding="utf-8") as f:
                            print("\n--- List of Server ---")
                            print(f.read())
                            print("------------------------------\n")
                        os.remove(".temp_list.txt") # Xóa file tạm sau khi in ra màn hình
                    except FileNotFoundError:
                        pass
        elif command == "PASV":
            if client.enter_passive_mode():
                print("[+] UDP Data Channel successfully prepared and SYN packet sent!")
                client.active_mode = False
            else:
                print("[-] Failed to enter Passive Mode.")
        elif command == "PORT" and len(parts) > 1:
            # Send the PORT command to the server first
            resp = client.send_command(cmd_input)
            print(f"[Server] {resp}")
            
            if resp.startswith("200"):
                p_parts = parts[1].split(',')
                client.data_ip = f"{p_parts[0]}.{p_parts[1]}.{p_parts[2]}.{p_parts[3]}"
                client.data_port = (int(p_parts[4]) * 256) + int(p_parts[5])
                
                # Create and BIND the socket for Active Mode listening
                client.data_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client.data_sock.bind(('0.0.0.0', client.data_port))
                client.active_mode = True
                print(f"[+] Active Mode UDP socket bound and listening on port {client.data_port}")
        else:
            # Send standard commands directly to the control channel (USER, PASS, PWD, CWD, HASH)
            print(f"[Server] {client.send_command(cmd_input)}")

if __name__ == "__main__":
    main()
