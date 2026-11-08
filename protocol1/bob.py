"""Protocol I - Bob (PPT 3): RSA 키쌍을 만들어 보낸다.
실행: python3 protocol1/bob.py -p 5555
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용
import argparse
import socket

from crypto_utils import recv_json, rsa_generate_keypair, send_json

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", type=int, required=True)
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

    # 2. RSA 키쌍 생성 후 p, q와 함께 보내기
    e, d, p, q = rsa_generate_keypair()
    send_json(conn, {"opcode": 0, "type": "RSAKey", "private": d, "public": e,
                     "parameter": {"p": p, "q": q}})
    conn.close()
