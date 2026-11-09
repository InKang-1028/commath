"""Protocol I - Bob (PPT 3): RSA 키쌍을 만들어 보낸다.
실행: python3 protocol1/bob.py        (포트 5551)
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용

from crypto_utils import bob_args, expect, rsa_generate_keypair, send_json, serve


def handle(conn):
    # 1. Alice의 요청 받기
    expect(conn, 0, "RSAKey")
    respond(conn)


def respond(conn):
    # 2. RSA 키쌍 생성 후 p, q와 함께 보내기
    e, d, p, q = rsa_generate_keypair()
    send_json(conn, {"opcode": 0, "type": "RSAKey", "private": d, "public": e,
                     "parameter": {"p": p, "q": q}})


if __name__ == "__main__":
    args = bob_args(5551)
    serve(args.port, handle, args.addr)
