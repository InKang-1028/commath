"""Protocol II - Alice (PPT 4~7): RSA로 AES 키를 보내고, AES로 메시지를 주고받는다.
실행: python3 protocol2/alice.py -a 127.0.0.1 -p 5555 -m world
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용
import argparse
import random
import socket

from crypto_utils import aes_decrypt, aes_encrypt, recv_json, send_json

parser = argparse.ArgumentParser()
parser.add_argument("-a", "--addr", required=True)
parser.add_argument("-p", "--port", type=int, required=True)
parser.add_argument("-m", "--message", default="world")
args = parser.parse_args()

conn = socket.create_connection((args.addr, args.port))

# 1. RSA 프로토콜 시작 요청
send_json(conn, {"opcode": 0, "type": "RSA"})

# 2. Bob의 공개키 (e, n) 받기
msg = recv_json(conn)
e = msg["public"]
n = msg["parameter"]["n"]

# 3. 랜덤 대칭키(32바이트) 생성 -> 한 바이트씩 RSA 암호화 (c = m^e mod n)
key = random.randbytes(32)
encrypted_key = [pow(b, e, n) for b in key]
send_json(conn, {"opcode": 2, "type": "RSA", "encrypted_key": encrypted_key})

# 4. Bob의 AES 메시지 받아서 복호화
msg = recv_json(conn)
print("Bob이 보낸 메시지:", aes_decrypt(key, msg["encryption"]))

# 5. 내 메시지를 AES로 암호화해서 보내기
send_json(conn, {"opcode": 2, "type": "AES", "encryption": aes_encrypt(key, args.message)})

conn.close()
