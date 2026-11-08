"""Protocol I - Alice (PPT 3): RSA 키를 요청하고 검증한다.
실행: python3 protocol1/alice.py -a 127.0.0.1 -p 5555
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용
import argparse
import socket

from crypto_utils import is_prime, recv_json, rsa_check_keypair, send_json

parser = argparse.ArgumentParser()
parser.add_argument("-a", "--addr", required=True)
parser.add_argument("-p", "--port", type=int, required=True)
args = parser.parse_args()

conn = socket.create_connection((args.addr, args.port))

# 1. RSA 키 요청
send_json(conn, {"opcode": 0, "type": "RSAKey"})

# 2. Bob이 보낸 키와 p, q 받기
msg = recv_json(conn)
d = msg["private"]
e = msg["public"]
p = msg["parameter"]["p"]
q = msg["parameter"]["q"]

# 3. p, q 소수 판정 (400~500 범위 포함)
p_ok = is_prime(p) and 400 <= p <= 500
q_ok = is_prime(q) and 400 <= q <= 500
print("p =", p, "-> 소수 판정:", "PASS" if p_ok else "FAIL")
print("q =", q, "-> 소수 판정:", "PASS" if q_ok else "FAIL")

# 4. 키쌍 검증 후 출력
print("공개키 e =", e, ", n =", p * q)
print("개인키 d =", d)
if p_ok and q_ok and rsa_check_keypair(e, d, p, q):
    print("RSA 키쌍: CORRECT")
else:
    print("RSA 키쌍: INCORRECT")

conn.close()
