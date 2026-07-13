import socket
import threading
import os
import random
import struct
import hashlib
import datetime
import uuid

# Custom UDP Header (11 bytes header + Payload)
# Format:
# 'I' = Unsigned int (4 bytes) - Sequence Number
# 'I' = Unsigned int (4 bytes) - Acknowledgment Number
# 'B' = Unsigned char (1 byte) - Flags (SYN, ACK, FIN, DATA)
# 'H' = Unsigned short (2 bytes) - Checksum

HEADER_FORMAT = '!IIBH'  # '!' đảm bảo network byte order
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# Định nghĩa Flags ở dạng bitmask
FLAG_SYN  = 0x01  # Bắt đầu truyền
FLAG_ACK  = 0x02  # Xác nhận
FLAG_DATA = 0x04  # Gói tin chứa dữ liệu
FLAG_FIN  = 0x08  # Kết thúc truyền

def make_packet(seq_num, ack_num, flags, data=b""):
    """Đóng gói Header và Payload thành một UDP packet hoàn chỉnh"""
    # Gán checksum = 0 để tính toán lúc đầu
    header = struct.pack(HEADER_FORMAT, seq_num, ack_num, flags, 0)
    packet_without_checksum = header + data
    checksum_val = 0
    # Đóng gói lại với checksum thực tế
    final_header = struct.pack(HEADER_FORMAT, seq_num, ack_num, flags, checksum_val)
    return final_header + data

def calculate_checksum(data):
    """Tính toán Checksum 16-bit cho gói tin (16-bit = 2 byte, luôn đảm bảo chia đc cho 2)"""
    if len(data) % 2 == 1:
        data += b'\0' # Đệm thêm 1 byte null nếu độ dài lẻ
    checksum = 0
    # Cắt dữ liệu thành các khối 16-bit và cộng lại
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + (data[i+1])
        checksum += word
        # Xử lý tràn bit (carry)
        checksum = (checksum & 0xffff) + (checksum >> 16)
    return (~checksum) & 0xffff

# Cấu hình cơ bản cho Server
HOST = '0.0.0.0'
CONTROL_PORT = 2121  # Cổng cho Control Channel

VALID_USERS = {
    "admin1": "123456",
    "admin2": "654321",
}

class ClientSession(threading.Thread):

    def __init__(self, control_sock, client_addr):
        super().__init__()
        self.control_sock = control_sock
        self.client_addr = client_addr
        # Trạng thái session
        self.is_authenticated = False
        self.username = ""
        self.current_dir = os.getcwd()
        # Thông tin Data Channel (UDP)
        self.data_mode = None  # 'ACTIVE' hoặc 'PASSIVE'
        self.data_ip = None
        self.data_port = None
        self.data_sock = None  # Socket UDP dùng để truyền dữ liệu
        self.rename_from_path = None # Trạng thái tạm thời cho RNFR/RNTO
        self.transfer_type = 'A'  # Mặc định là 'A' (ASCII), có thể đổi sang 'I' (Image/Binary)
        self.transfer_mode = 'S'  # Mặc định là 'S' (Stream)

    def run(self):
        print(f"[+] New Client connects from: {self.client_addr}")
        self.send_response("220 Hybrid FTP Server Ready\r\n")
        try:
            while True:
                # Đọc dữ liệu từ Control Channel TCP
                data = self.control_sock.recv(1024).decode('utf-8')
                if not data:
                    break
                request = data.strip()
                print(f"[Command Received] {request}")
                # Phân tách lệnh và tham số
                parts = request.split(' ', 1)
                command = parts[0].upper()
                arg = parts[1].strip() if len(parts) > 1 else ""
                # Định nghĩa các lệnh cơ bản của FTP
                if command == "USER":
                    self.handle_user(arg)
                elif command == "PASS":
                    self.handle_pass(arg)
                if command == "QUIT":
                    self.send_response("221 Goodbye\r\n")
                    break
                elif command == "NOOP":
                    self.send_response("200 Command OK\r\n")
                else:
                    # Chặn các lệnh khác nếu chưa đăng nhập
                    if not self.is_authenticated:
                        self.send_response("530 Not logged in\r\n")
                    else:
                        if command == "PWD":
                            self.handle_pwd()
                        elif command == "CWD":
                            self.handle_cwd(arg)
                        elif command == "CDUP":
                            self.handle_cwd("..")
                        elif command == "MKD":
                            self.handle_mkd(arg)
                        elif command == "RMD":
                            self.handle_rmd(arg)
                        elif command == "PORT":
                            self.handle_port(arg)
                        elif command == "PASV":
                            self.handle_pasv()
                        elif command == "LIST":
                            self.handle_list(arg)
                        elif command == "RETR":
                            self.handle_retr(arg)
                        elif command == "STOR":
                            self.handle_stor(arg)
                        elif command == "HASH":
                            self.handle_hash(arg)
                        elif command == "SIZE":
                            self.handle_size(arg)
                        elif command == "DELE":
                            self.handle_dele(arg)
                        elif command == "RNFR":
                            self.handle_rnfr(arg)
                        elif command == "RNTO":
                            self.handle_rnto(arg)
                        elif command == "TYPE":
                            self.handle_type(arg)
                        elif command == "MODE":
                            self.handle_mode(arg)
                        elif command == "APPE":
                            self.handle_appe(arg)
                        elif command == "STOU":
                            self.handle_stou()
                        elif command == "NLST":
                            self.handle_nlst(arg)
                        elif command == "MDTM":
                            self.handle_mdtm(arg)
                        elif command == "STAT":
                            self.handle_stat(arg)
                        elif command == "HELP":
                            self.handle_help(arg)
                        elif command == "ABOR":
                            self.send_response("226 Abort successful.\r\n")
                        else:
                            self.send_response("502 Command not implemented\r\n")
        except ConnectionResetError:
            print(f"[-] Client {self.client_addr} stop connecting")
        finally:
            print(f"[*] Stop session: {self.client_addr}")
            self.control_sock.close()

    def send_response(self, message):
        """Hàm hỗ trợ gửi phản hồi về client"""
        self.control_sock.sendall(message.encode('utf-8'))

    def handle_user(self, arg):
        if not arg:
            self.send_response("501 Syntax error in parameters or arguments\r\n") # 
            return
        self.username = arg
        self.send_response("331 Username OK, need password\r\n")
    
    def handle_pass(self, arg):
        if not self.username:
            self.send_response("503 Bad sequence of commands\r\n")
            return
        if self.username in VALID_USERS and VALID_USERS[self.username] == arg:
            self.is_authenticated = True
            self.send_response("230 Login successful\r\n")
        else:
            self.username = ""
            self.send_response("530 Not logged in\r\n")
    
    # Cú pháp: PORT h1,h2,h3,h4,p1,p2
    def handle_port(self, arg):
        """Active Mode: Client gửi IP và Port đang chờ kết nối"""
        try:
            parts = arg.split(',')
            if len(parts) != 6:
                raise ValueError
            # Tính toán lại IP và Port
            self.data_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}"
            self.data_port = (int(parts[4]) * 256) + int(parts[5])
            self.data_mode = "ACTIVE"
            # Tạo sẵn UDP Socket cho Server
            if self.data_sock:
                self.data_sock.close()
            self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.send_response("200 PORT command successful\r\n")
        except ValueError:
            self.send_response("501 Syntax error in parameters\r\n")

    def handle_pasv(self):
        """Passive Mode: Server mở một Port ngẫu nhiên và báo cho Client"""
        # Chọn một port UDP ngẫu nhiên từ 1024 đến 65535
        pasv_port = random.randint(1024, 65535)
        server_ip = self.control_sock.getsockname()[0]
        if self.data_sock:
            self.data_sock.close()
        # Khởi tạo và Bind UDP Socket tại Server
        self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.data_sock.bind((server_ip, pasv_port))
        self.data_mode = "PASSIVE"
        self.data_ip = server_ip
        self.data_port = pasv_port
        # Tính toán p1, p2
        p1 = pasv_port // 256
        p2 = pasv_port % 256
        h1, h2, h3, h4 = server_ip.split('.')
        response = f"227 Entering Passive Mode ({h1},{h2},{h3},{h4},{p1},{p2})\r\n"
        self.send_response(response)
    
    # RDT (STOP-AND-WAIT)
    def rdt_send(self, payload):
        """Sends data over UDP with Stop-and-Wait fragmentation"""
        if not self.data_sock or not self.data_ip or not self.data_port:
            self.send_response("425 Can't open data connection\r\n")
            return False
        chunk_size = 1024  # Safe payload size below standard MTU
        seq_num = 1
        timeout = 2.0
        self.data_sock.settimeout(timeout)
        target_addr = (self.data_ip, self.data_port)
        total_bytes = len(payload)
        offset = 0
        while offset < total_bytes:
            is_last_chunk = (offset + chunk_size) >= total_bytes
            flags = FLAG_DATA | FLAG_FIN if is_last_chunk else FLAG_DATA
            chunk = payload[offset:offset + chunk_size]
            # Pack Header and Checksum
            header = struct.pack(HEADER_FORMAT, seq_num, 0, flags, 0)
            chksum = calculate_checksum(header + chunk)
            final_packet = struct.pack(HEADER_FORMAT, seq_num, 0, flags, chksum) + chunk
            max_retries = 3
            attempts = 0
            ack_received = False
            # Stop-and-Wait transmission loop for the current chunk
            while attempts < max_retries and not ack_received:
                try:
                    self.data_sock.sendto(final_packet, target_addr)
                    # Wait for ACK
                    ack_data, _ = self.data_sock.recvfrom(1024)
                    if len(ack_data) >= HEADER_SIZE:
                        r_seq, r_ack, r_flags, r_chksum = struct.unpack(HEADER_FORMAT, ack_data[:HEADER_SIZE])
                        if (r_flags & FLAG_ACK) and r_ack == seq_num:
                            ack_received = True
                except socket.timeout:
                    attempts += 1
                    print(f"[RDT] Timeout! Resending Seq={seq_num}, Attempt {attempts}/{max_retries}")
            if not ack_received:
                print("[RDT] Max retries exceeded. Aborting transfer.")
                return False
            offset += chunk_size
            seq_num += 1
        return True

    def rdt_recv(self, file_path, write_mode='wb'):
        """Receives data over UDP and writes to disk (Stop-and-Wait)"""
        if not self.data_sock:
            self.send_response("425 Can't open data connection\r\n")
            return False
        self.data_sock.settimeout(5.0)  # Wait up to 5s for incoming packets
        expected_seq = 1
        try:
            with open(file_path, write_mode) as f:
                while True:
                    try:
                        packet, addr = self.data_sock.recvfrom(2048)
                        if len(packet) < HEADER_SIZE:
                            continue
                        # Unpack header
                        header_bytes = packet[:HEADER_SIZE]
                        payload = packet[HEADER_SIZE:]
                        r_seq, r_ack, r_flags, r_chksum = struct.unpack(HEADER_FORMAT, header_bytes)
                        # Verify Checksum
                        temp_header = struct.pack(HEADER_FORMAT, r_seq, r_ack, r_flags, 0)
                        if calculate_checksum(temp_header + payload) != r_chksum:
                            print(f"[RDT] Checksum failed for Seq={r_seq}. Dropping packet.")
                            continue # Ignore corrupted packet, let sender timeout
                        # Process in-order packet
                        if r_seq == expected_seq:
                            f.write(payload)
                            # Send ACK back
                            ack_header = struct.pack(HEADER_FORMAT, 0, expected_seq, FLAG_ACK, 0)
                            ack_chksum = calculate_checksum(ack_header)
                            final_ack = struct.pack(HEADER_FORMAT, 0, expected_seq, FLAG_ACK, ack_chksum)
                            self.data_sock.sendto(final_ack, addr)
                            if r_flags & FLAG_FIN:
                                return True # End of file received successfully
                            expected_seq += 1
                        # Handle duplicate/delayed packets (Client re-sent because our ACK was lost)
                        elif r_seq < expected_seq:
                            # Re-ACK the old packet so the sender can move forward
                            ack_header = struct.pack(HEADER_FORMAT, 0, r_seq, FLAG_ACK, 0)
                            ack_chksum = calculate_checksum(ack_header)
                            final_ack = struct.pack(HEADER_FORMAT, 0, r_seq, FLAG_ACK, ack_chksum)
                            self.data_sock.sendto(final_ack, addr)
                    except socket.timeout:
                        print("[RDT] Timeout waiting for data packets.")
                        return False
        except Exception as e:
            print(f"File IO Error: {e}")
            return False

    def handle_list(self, arg):
        """LIST: Gửi danh sách thư mục qua Data Channel"""
        target_path = self.current_dir
        if arg:
            target_path = os.path.abspath(os.path.join(self.current_dir, arg))
        if not os.path.exists(target_path):
            self.send_response("450 Requested file action not taken. File/Directory unavailable\r\n")
            return
        # 1. Thông báo qua Control Channel là chuẩn bị mở Data Channel
        self.send_response("150 File status okay; about to open data connection\r\n")
        # 2. Thu thập danh sách file
        try:
            listing = ""
            for item in os.listdir(target_path):
                full_path = os.path.join(target_path, item)
                size = os.path.getsize(full_path)
                item_type = "d" if os.path.isdir(full_path) else "-"
                # Định dạng đơn giản: loại, kích thước, tên file
                listing += f"{item_type}rw-r--r-- 1 ftp ftp {size:>8} {item}\r\n"
            payload = listing.encode('utf-8')
            # 3. Gửi danh sách qua UDP
            success = self.rdt_send(payload)
            if success:
                self.send_response("226 Transfer complete\r\n")
            else:
                self.send_response("426 Connection closed; transfer aborted\r\n")  
        except Exception as e:
            self.send_response("550 Error reading directory\r\n")
        finally:
            if self.data_sock:
                self.data_sock.close()
                self.data_sock = None

    def handle_pwd(self):
        """PWD: In đường dẫn hiện tại"""
        self.send_response(f'257 "{self.current_dir}" is the current directory\r\n')

    def handle_cwd(self, path):
        """CWD và CDUP: Thay đổi thư mục làm việc (CWD: Change Working Directory, CDUP: Change to Parent Directory)"""
        if not path:
            self.send_response("501 Syntax error in parameters\r\n")
            return
        # Tính toán đường dẫn tuyệt đối để tránh Path Traversal
        # Giả sử server chỉ cho truy cập "/home/ftp", tuy nhiên người dùng khi truy cập lại đang ở "home/ftp/uploads"
        # Nếu cho phép nối đuôi trực tiếp, user nhập: ../../../../etc, Linux trả về /etc, tức là đã thoát ra khỏi thư mục cho phép
        # Xử lý abspath (bỏ ..): home/ftp/etc
        target_dir = os.path.abspath(os.path.join(self.current_dir, path))
        if os.path.isdir(target_dir):
            self.current_dir = target_dir
            self.send_response("250 Requested file action OK, directory changed\r\n")
        else:
            self.send_response("550 Requested action not taken. File/Directory unavailable\r\n")

    def handle_mkd(self, dirname):
        """MKD: Tạo thư mục mới"""
        if not dirname:
            self.send_response("501 Syntax error in parameters\r\n")
            return
        target_dir = os.path.abspath(os.path.join(self.current_dir, dirname))
        try:
            os.makedirs(target_dir, exist_ok=False)
            self.send_response(f'257 "{target_dir}" directory created\r\n')
        except FileExistsError:
            self.send_response("550 Directory already exists\r\n")
        except Exception as e:
            self.send_response("550 Cannot create directory\r\n")

    def handle_rmd(self, dirname):
        """RMD: Xóa thư mục rỗng"""
        if not dirname:
            self.send_response("501 Syntax error in parameters\r\n")
            return
        target_dir = os.path.abspath(os.path.join(self.current_dir, dirname))
        try:
            os.rmdir(target_dir) # rmdir chỉ xóa thư mục rỗng
            self.send_response("250 Requested file action OK, directory removed\r\n")
        except FileNotFoundError:
            self.send_response("550 Directory not found\r\n")
        except OSError:
            self.send_response("550 Directory not empty or access denied\r\n")
    
    def handle_retr(self, filename):
        """RETR (Retrieve): Download file from server to client"""
        if not filename:
            self.send_response("501 Syntax error in parameters\r\n")
            return
        filepath = os.path.abspath(os.path.join(self.current_dir, filename))
        if not os.path.isfile(filepath):
            self.send_response("550 File not found\r\n")
            return
        self.send_response(f"150 Opening binary mode data connection for {filename}\r\n")
        try:
            # Read the entire file into memory (For huge files, read in chunks inside rdt_send)
            with open(filepath, 'rb') as f:
                file_data = f.read()
            if self.rdt_send(file_data):
                self.send_response("226 Transfer complete\r\n")
            else:
                self.send_response("426 Connection closed; transfer aborted\r\n")
        except IOError:
            self.send_response("550 Error reading file\r\n")
        finally:
            if self.data_sock:
                self.data_sock.close()
                self.data_sock = None

    def handle_stor(self, filename):
        """STOR (Store): Upload file from client to server"""
        if not filename:
            self.send_response("501 Syntax error in parameters\r\n")
            return
        filepath = os.path.abspath(os.path.join(self.current_dir, filename))
        self.send_response("150 Ok to send data\r\n")
        if self.rdt_recv(filepath):
            self.send_response("226 Transfer complete\r\n")
        else:
            self.send_response("426 Connection closed; transfer aborted\r\n")
        if self.data_sock:
            self.data_sock.close()
            self.data_sock = None
    
    # Xác minh, quản lý File
    def handle_hash(self, filename):
        """HASH: Trả về SHA-256 của file để Client kiểm tra tính toàn vẹn"""
        if not filename:
            self.send_response("501 Syntax error in parameters.\r\n")
            return
        filepath = os.path.abspath(os.path.join(self.current_dir, filename))
        if not os.path.isfile(filepath):
            self.send_response("550 File not found.\r\n")
            return
        try:
            sha256_hash = hashlib.sha256()
            # Đọc file theo từng khối để tiết kiệm RAM với file dung lượng lớn
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            hash_hex = sha256_hash.hexdigest()
            self.send_response(f"213 SHA-256 {hash_hex}\r\n")
        except IOError:
            self.send_response("550 Error reading file for hashing.\r\n")

    def handle_size(self, filename):
        """SIZE: Trả về kích thước File"""
        if not filename:
            self.send_response("501 Syntax error in parameters.\r\n")
            return
        filepath = os.path.abspath(os.path.join(self.current_dir, filename))
        if os.path.isfile(filepath):
            file_size = os.path.getsize(filepath)
            self.send_response(f"213 {file_size}\r\n")
        else:
            self.send_response("550 File not found.\r\n")

    def handle_dele(self, filename):
        """DELE: Xóa file trên server"""
        if not filename:
            self.send_response("501 Syntax error in parameters.\r\n")
            return
        filepath = os.path.abspath(os.path.join(self.current_dir, filename))
        if os.path.isfile(filepath):
            try:
                os.remove(filepath)
                self.send_response("250 Requested file action OK, file deleted.\r\n")
            except OSError:
                self.send_response("450 Requested file action not taken. File in use or access denied.\r\n")
        else:
            self.send_response("550 File not found.\r\n")

    def handle_rnfr(self, filename):
        """RNFR (Rename From): Chỉ định file cần đổi tên"""
        if not filename:
            self.send_response("501 Syntax error in parameters.\r\n")
            return
        filepath = os.path.abspath(os.path.join(self.current_dir, filename))
        if os.path.isfile(filepath) or os.path.isdir(filepath):
            self.rename_from_path = filepath
            self.send_response("350 Requested file action pending further information (Send RNTO).\r\n")
        else:
            self.send_response("550 File or directory not found.\r\n")

    def handle_rnto(self, filename):
        """RNTO (Rename To): Hoàn tất đổi tên đã khởi tạo bởi RNFR"""
        if not self.rename_from_path:
            self.send_response("503 Bad sequence of commands. Send RNFR first.\r\n")
            return
        if not filename:
            self.send_response("501 Syntax error in parameters.\r\n")
            return
        new_filepath = os.path.abspath(os.path.join(self.current_dir, filename))
        try:
            os.rename(self.rename_from_path, new_filepath)
            self.rename_from_path = None  # Reset lại trạng thái
            self.send_response("250 Requested file action OK, file renamed.\r\n")
        except OSError:
            self.send_response("553 Requested action not taken. File name not allowed.\r\n")
    
    def handle_type(self, arg):
        """TYPE: Đặt kiểu dữ liệu truyền tải (A = ASCII, I = Image/Binary)"""
        if arg in ['A', 'I']:
            self.transfer_type = arg
            self.send_response(f"200 Type set to {arg}.\r\n")
        else:
            self.send_response("504 Command not implemented for that parameter.\r\n")

    def handle_mode(self, arg):
        """MODE: Đặt chế độ truyền tải (S = Stream, B = Block, C = Compressed)"""
        if arg in ['S', 'B', 'C']:
            self.transfer_mode = arg
            self.send_response(f"200 Mode set to {arg}.\r\n")
        else:
            self.send_response("504 Command not implemented for that parameter.\r\n")

    def handle_appe(self, filename):
        """APPE: Upload và ghi nối tiếp vào cuối file (nếu chưa có thì tạo mới)"""
        if not filename:
            self.send_response("501 Syntax error in parameters.\r\n")
            return
        filepath = os.path.abspath(os.path.join(self.current_dir, filename))
        self.send_response("150 Ok to send data, appending to file.\r\n")
        # Gọi rdt_recv với mode 'ab' (append binary)
        if self.rdt_recv(filepath, write_mode='ab'):
            self.send_response("226 Transfer complete.\r\n")
        else:
            self.send_response("426 Connection closed; transfer aborted.\r\n")
        if self.data_sock:
            self.data_sock.close()
            self.data_sock = None

    def handle_stou(self):
        """STOU: Upload file nhưng Server tự sinh tên file độc nhất để chống ghi đè"""
        unique_filename = f"upload_{uuid.uuid4().hex[:8]}.dat"
        filepath = os.path.abspath(os.path.join(self.current_dir, unique_filename))
        self.send_response(f"150 FILE: {unique_filename}\r\n")
        if self.rdt_recv(filepath, write_mode='wb'):
            self.send_response("226 Transfer complete.\r\n")
        else:
            self.send_response("426 Connection closed; transfer aborted.\r\n")
        if self.data_sock:
            self.data_sock.close()
            self.data_sock = None

    def handle_nlst(self, arg):
        """NLST: Trả về danh sách file rút gọn (chỉ có tên) qua Data Channel"""
        target_path = self.current_dir
        if arg:
            target_path = os.path.abspath(os.path.join(self.current_dir, arg))
        if not os.path.exists(target_path):
            self.send_response("450 Requested action not taken. Directory unavailable.\r\n")
            return
        self.send_response("150 File status okay; about to open data connection.\r\n")
        try:
            listing = ""
            for item in os.listdir(target_path):
                listing += f"{item}\r\n"
            payload = listing.encode('utf-8')
            if self.rdt_send(payload):
                self.send_response("226 Transfer complete.\r\n")
            else:
                self.send_response("426 Connection closed; transfer aborted.\r\n")
        except Exception:
            self.send_response("550 Error reading directory.\r\n")
        finally:
            if self.data_sock:
                self.data_sock.close()
                self.data_sock = None

    def handle_mdtm(self, filename):
        """MDTM: Trả về thời gian chỉnh sửa cuối cùng của file (Format: YYYYMMDDhhmmss)"""
        if not filename:
            self.send_response("501 Syntax error in parameters.\r\n")
            return
        filepath = os.path.abspath(os.path.join(self.current_dir, filename))
        if os.path.isfile(filepath):
            mtime = os.path.getmtime(filepath)
            # Chuyển đổi timestamp sang định dạng YYYYMMDDhhmmss
            dt = datetime.datetime.fromtimestamp(mtime)
            formatted_time = dt.strftime('%Y%m%d%H%M%S')
            self.send_response(f"213 {formatted_time}\r\n")
        else:
            self.send_response("550 File not found.\r\n")

    def handle_stat(self, arg):
        """STAT: Trả về trạng thái server qua kênh TCP"""
        status_msg = (
            f"211-Server Status:\r\n"
            f" Logged in as: {self.username}\r\n"
            f" Type: {self.transfer_type}, Mode: {self.transfer_mode}\r\n"
            f" Data connection mode: {self.data_mode}\r\n"
            f"211 End of status.\r\n"
        )
        self.send_response(status_msg)

    def handle_help(self, arg):
        """HELP: Trả về danh sách lệnh hỗ trợ"""
        help_msg = (
            "214-The following commands are recognized:\r\n"
            " USER PASS QUIT NOOP PWD CWD CDUP MKD RMD\r\n"
            " LIST NLST STAT SIZE MDTM TYPE MODE PORT\r\n"
            " PASV RETR STOR STOU APPE DELE RNFR RNTO\r\n"
            " HASH ABOR HELP\r\n"
            "214 Help OK.\r\n"
        )
        self.send_response(help_msg)

def start_server():
    # Khởi tạo TCP Socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((HOST, CONTROL_PORT))
        server_sock.listen(5)
        print(f"Server is hearing from port TCP {CONTROL_PORT}...")
        while True:
            client_sock, client_addr = server_sock.accept()
            # Khởi tạo một thread mới cho mỗi client để tách riêng từng session
            session = ClientSession(client_sock, client_addr)
            session.start()
    except KeyboardInterrupt:
        print("\n[*] Shut down server...")
    finally:
        server_sock.close()

if __name__ == "__main__":
    start_server()
