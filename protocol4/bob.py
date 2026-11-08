"""Protocol IV - Bob (PPT 12~13): 일부러 잘못된 p 또는 g를 보내서 Alice의 오류 처리를 확인한다.
Alice 쪽은 protocol3/alice.py를 그대로 쓴다 (3, 4번 단계에서 검사함).

실행: python3 protocol4/bob.py -p 5555 -f prime        # IV-I : 소수가 아닌 p
      python3 protocol4/bob.py -p 5555 -f generator    # IV-II: 생성원이 아닌 g
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용
import argparse
import random
import socket

from crypto_utils import (random_generator, random_non_generator, random_non_prime, random_prime,
                          recv_json, send_json)

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", type=int, required=True)
parser.add_argument("-f", "--fault", choices=["prime", "generator"], required=True)
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

    # 2. 잘못된 파라미터 만들기
    if args.fault == "prime":
        p = random_non_prime()          # IV-I : 합성수 p
        g = random.randint(2, p - 1)
    else:
        p = random_prime()
        g = random_non_generator(p)     # IV-II: 생성원이 아닌 g
    private = random.randint(2, p - 2)
    public = pow(g, private, p)
    send_json(conn, {"opcode": 1, "type": "DH", "public": public, "parameter": {"p": p, "g": g}})

    # 3. Alice가 보낸 오류 메시지 출력
    msg = recv_json(conn)
    if msg and msg["opcode"] == 3:
        print("Alice가 보낸 오류:", msg["error"])

    conn.close()
