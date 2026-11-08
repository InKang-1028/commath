"""Protocol III - Bob (PPT 8~11): DH 파라미터와 공개키를 주고, AES로 메시지를 주고받는다.
실행: python3 protocol3/bob.py -p 5555 -m hello
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용
import argparse
import random
import socket

from crypto_utils import (aes_decrypt, aes_encrypt, dh_secret_to_aes_key, random_generator,
                          random_prime, recv_json, send_json)

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

    # 2. p(400~500 소수), g(생성원), 내 DH 키쌍 생성 -> 보내기
    p = random_prime()
    g = random_generator(p)
    private = random.randint(2, p - 2)
    public = pow(g, private, p)
    send_json(conn, {"opcode": 1, "type": "DH", "public": public, "parameter": {"p": p, "g": g}})

    # 3. Alice의 공개키 받기 (오류 메시지가 오면 출력하고 끝)
    msg = recv_json(conn)
    if msg["opcode"] == 3:
        print("Alice가 보낸 오류:", msg["error"])
        conn.close()
        continue

    # 4. 공유 비밀 계산 -> AES 키 만들기
    secret = pow(msg["public"], private, p)
    key = dh_secret_to_aes_key(secret)
    print("공유 비밀 =", secret, ", AES 키 =", key.hex())

    # 5. 내 메시지를 AES로 암호화해서 보내기
    send_json(conn, {"opcode": 2, "type": "AES", "encryption": aes_encrypt(key, args.message)})

    # 6. Alice의 AES 메시지 받아서 복호화
    msg = recv_json(conn)
    print("Alice가 보낸 메시지:", aes_decrypt(key, msg["encryption"]))

    conn.close()
