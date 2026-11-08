"""Protocol II - Bob (PPT 4~7): RSA 공개키를 주고, 받은 AES 키로 메시지를 주고받는다.
실행: python3 protocol2/bob.py -p 5555 -m hello
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용
import argparse
import socket

from crypto_utils import aes_decrypt, aes_encrypt, recv_json, rsa_generate_keypair, send_json

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", type=int, required=True)
parser.add_argument("-m", "--message", default="hello")
args = parser.parse_args()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", args.port))
server.listen()
print("Bob is listening on port", args.port)

while True:
    conn, addr = server.accept()
    print("\n=== Alice connected:", addr)

    # 1. Alice의 요청 받기
    msg = recv_json(conn)

    # 2. RSA 키쌍 생성 -> 공개키 (e, n) 보내기
    e, d, p, q = rsa_generate_keypair()
    n = p * q
    send_json(conn, {"opcode": 1, "type": "RSA", "public": e, "parameter": {"n": n}})

    # 3. 암호화된 대칭키 받아서 한 바이트씩 RSA 복호화 (m = c^d mod n)
    msg = recv_json(conn)
    key = bytes(pow(c, d, n) for c in msg["encrypted_key"])

    # 4. 내 메시지를 AES로 암호화해서 보내기
    send_json(conn, {"opcode": 2, "type": "AES", "encryption": aes_encrypt(key, args.message)})

    # 5. Alice의 AES 메시지 받아서 복호화
    msg = recv_json(conn)
    print("Alice가 보낸 메시지:", aes_decrypt(key, msg["encryption"]))

    conn.close()
