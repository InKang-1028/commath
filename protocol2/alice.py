"""Protocol II - Alice (PPT 4~7): RSA로 AES 키를 보내고, AES로 메시지를 주고받는다.
실행: python3 protocol2/alice.py                  (테스트 서버 10.41.12.51:5552)
      python3 protocol2/alice.py -a 127.0.0.1 -m world
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용
import random

from crypto_utils import aes_decrypt, aes_encrypt, alice_args, expect, run_alice, send_json


def handle(conn, message):
    # 1. RSA 프로토콜 시작 요청
    send_json(conn, {"opcode": 0, "type": "RSA"})

    # 2. Bob의 공개키 (e, n) 받기
    msg = expect(conn, 1, "RSA")
    e = msg["public"]
    n = msg["parameter"]["n"]

    # 3. 랜덤 대칭키(32바이트) 생성 -> 한 바이트씩 RSA 암호화 (c = m^e mod n)
    key = random.randbytes(32)
    encrypted_key = [pow(b, e, n) for b in key]
    send_json(conn, {"opcode": 2, "type": "RSA", "encrypted_key": encrypted_key})

    # 4. Bob의 AES 메시지 받아서 복호화
    msg = expect(conn, 2, "AES")
    print("Bob이 보낸 메시지:", aes_decrypt(key, msg["encryption"]))

    # 5. 내 메시지를 AES로 암호화해서 보내기
    send_json(conn, {"opcode": 2, "type": "AES", "encryption": aes_encrypt(key, message)})


if __name__ == "__main__":
    args = alice_args(5552, "world")
    run_alice(args.addr, args.port, lambda conn: handle(conn, args.message))
