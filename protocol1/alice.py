"""Protocol I - Alice (PPT 3): RSA 키를 요청하고 검증한다.
실행: python3 protocol1/alice.py                  (테스트 서버 10.41.12.51:5551)
      python3 protocol1/alice.py -a 127.0.0.1     (로컬 Bob)
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용

from crypto_utils import alice_args, expect, is_prime, rsa_check_keypair, run_alice, send_json, to_int


def handle(conn):
    # 1. RSA 키 요청
    send_json(conn, {"opcode": 0, "type": "RSAKey"})

    # 2. Bob이 보낸 키와 p, q 받기
    msg = expect(conn, 0, "RSAKey")
    d = to_int(msg["private"])
    e = to_int(msg["public"])
    p = to_int(msg["parameter"]["p"])
    q = to_int(msg["parameter"]["q"])

    # 3. p, q 소수 판정 (400~500 범위 포함)
    p_ok = is_prime(p) and 400 <= p <= 500
    q_ok = is_prime(q) and 400 <= q <= 500
    print("p =", p, "-> 소수 판정:", "PASS" if p_ok else "FAIL")
    print("q =", q, "-> 소수 판정:", "PASS" if q_ok else "FAIL")

    # 4. 키쌍 검증 후 출력
    print("공개키 e =", e, ", n =", p * q)
    print("개인키 d =", d)
    if p_ok and q_ok and p != q and rsa_check_keypair(e, d, p, q):
        print("RSA 키쌍: CORRECT")
    else:
        print("RSA 키쌍: INCORRECT")


if __name__ == "__main__":
    args = alice_args(5551)
    run_alice(args.addr, args.port, handle)
