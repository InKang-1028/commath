"""Protocol III - Alice (PPT 8~11): DH로 AES 키를 만들고 메시지를 주고받는다.
p나 g가 잘못되면 오류를 보내고 종료한다 (= Protocol IV, PPT 12~13).
실행: python3 protocol3/alice.py                  (테스트 서버 10.41.12.51:5553)
      python3 protocol3/alice.py -a 127.0.0.1 -m world
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용
import random

from crypto_utils import (aes_decrypt, aes_encrypt, alice_args, dh_secret_to_aes_key, expect,
                          is_generator, is_prime, run_alice, send_json)


def handle(conn, message):
    # 1. DH 프로토콜 시작 요청
    send_json(conn, {"opcode": 0, "type": "DH"})

    # 2. Bob의 공개키와 p, g 받기
    msg = expect(conn, 1, "DH")
    bob_public = msg["public"]
    p = msg["parameter"]["p"]
    g = msg["parameter"]["g"]

    # 3. p 소수 판정 -> 실패하면 오류 전송 후 종료 (Protocol IV-I)
    if not (is_prime(p) and 400 <= p <= 500):
        print("p =", p, "는 소수가 아님 -> 종료")
        send_json(conn, {"opcode": 3, "error": "incorrect prime number"})
        return
    print("p =", p, "-> 소수 판정: PASS")

    # 4. g 생성원 검증 -> 실패하면 오류 전송 후 종료 (Protocol IV-II)
    if not is_generator(g, p):
        print("g =", g, "는 생성원이 아님 -> 종료")
        send_json(conn, {"opcode": 3, "error": "incorrect generator"})
        return
    print("g =", g, "-> 생성원 검증: PASS")

    # 5. 내 DH 키쌍 생성 -> 공개키 보내기
    private = random.randint(2, p - 2)
    public = pow(g, private, p)
    send_json(conn, {"opcode": 1, "type": "DH", "public": public})

    # 6. 공유 비밀 계산 -> AES 키 만들기
    secret = pow(bob_public, private, p)
    key = dh_secret_to_aes_key(secret)
    print("공유 비밀 =", secret, ", AES 키 =", key.hex())

    # 7. Bob의 AES 메시지 받아서 복호화
    msg = expect(conn, 2, "AES")
    print("Bob이 보낸 메시지:", aes_decrypt(key, msg["encryption"]))

    # 8. 내 메시지를 AES로 암호화해서 보내기
    send_json(conn, {"opcode": 2, "type": "AES", "encryption": aes_encrypt(key, message)})


def main(default_port=5553):
    args = alice_args(default_port, "world")
    run_alice(args.addr, args.port, lambda conn: handle(conn, args.message))


if __name__ == "__main__":
    main()
