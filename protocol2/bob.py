"""Protocol II - Bob (PPT 4~7): RSA 공개키를 주고, 받은 AES 키로 메시지를 주고받는다.
실행: python3 protocol2/bob.py        (포트 5552, 메시지 hello)
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용

from crypto_utils import aes_decrypt, aes_encrypt, bob_args, expect, rsa_generate_keypair, send_json, serve


def handle(conn, message):
    # 1. Alice의 요청 받기
    expect(conn, 0, "RSA")
    respond(conn, message)


def respond(conn, message):
    # 2. RSA 키쌍 생성 -> 공개키 (e, n) 보내기
    e, d, p, q = rsa_generate_keypair()
    n = p * q
    send_json(conn, {"opcode": 1, "type": "RSA", "public": e, "parameter": {"n": n}})

    # 3. 암호화된 대칭키 받아서 한 바이트씩 RSA 복호화 (m = c^d mod n)
    msg = expect(conn, 2, "RSA")
    key = bytes(pow(c, d, n) for c in msg["encrypted_key"])
    if len(key) != 32:
        raise ValueError("대칭키가 32바이트가 아님 ({}바이트)".format(len(key)))

    # 4. 내 메시지를 AES로 암호화해서 보내기
    send_json(conn, {"opcode": 2, "type": "AES", "encryption": aes_encrypt(key, message)})

    # 5. Alice의 AES 메시지 받아서 복호화
    msg = expect(conn, 2, "AES")
    print("Alice가 보낸 메시지:", aes_decrypt(key, msg["encryption"]))


if __name__ == "__main__":
    args = bob_args(5552, "hello")
    serve(args.port, lambda conn: handle(conn, args.message))
