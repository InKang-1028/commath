"""Protocol III - Bob (PPT 8~11): DH 파라미터와 공개키를 주고, AES로 메시지를 주고받는다.
실행: python3 protocol3/bob.py        (포트 5553, 메시지 hello)
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용
import random

from crypto_utils import (aes_decrypt, aes_encrypt, bob_args, dh_secret_to_aes_key, expect,
                          random_generator, random_prime, send_json, serve, to_int)


def handle(conn, message):
    # 1. Alice의 요청 받기
    expect(conn, 0, "DH")
    respond(conn, message)


def respond(conn, message):
    # 2. p(범위 안의 소수, 기본 400~500), g(생성원), 내 DH 키쌍 생성 -> 보내기
    p = random_prime()
    g = random_generator(p)
    private = random.randint(2, p - 2)
    public = pow(g, private, p)
    send_json(conn, {"opcode": 1, "type": "DH", "public": public, "parameter": {"p": p, "g": g}})

    # 3. Alice의 공개키 받기 (opcode 3 오류가 오면 serve()가 출력하고 다음 연결로)
    msg = expect(conn, 1, "DH")

    # 4. 공유 비밀 계산 -> AES 키 만들기
    secret = pow(to_int(msg["public"]), private, p)
    key = dh_secret_to_aes_key(secret)
    print("공유 비밀 =", secret, ", AES 키 =", key.hex())

    # 5. 내 메시지를 AES로 암호화해서 보내기
    send_json(conn, {"opcode": 2, "type": "AES", "encryption": aes_encrypt(key, message)})

    # 6. Alice의 AES 메시지 받아서 복호화
    msg = expect(conn, 2, "AES")
    print("Alice가 보낸 메시지:", aes_decrypt(key, msg["encryption"]))


if __name__ == "__main__":
    args = bob_args(5553, "hello")
    serve(args.port, lambda conn: handle(conn, args.message), args.addr)
