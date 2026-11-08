"""Protocol IV - Bob (PPT 12~13): 일부러 잘못된 p 또는 g를 보내서 Alice의 오류 처리를 확인한다.
실행: python3 protocol4/bob.py                  (포트 5554, 연결마다 prime/generator 오류 랜덤)
      python3 protocol4/bob.py -f prime         # IV-I : 소수가 아닌 p
      python3 protocol4/bob.py -f generator     # IV-II: 생성원이 아닌 g
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용
import random

from crypto_utils import (bob_args, expect, random_non_generator, random_non_prime, random_prime,
                          send_json, serve)


def handle(conn, fault):
    # 1. Alice의 요청 받기
    expect(conn, 0, "DH")
    respond(conn, fault)


def respond(conn, fault):
    # 2. 잘못된 파라미터 만들기
    if fault == "random":
        fault = random.choice(["prime", "generator"])
    if fault == "prime":
        p = random_non_prime()          # IV-I : 합성수 p
        g = random.randint(2, p - 1)
    else:
        p = random_prime()
        g = random_non_generator(p)     # IV-II: 생성원이 아닌 g
    private = random.randint(2, p - 2)
    public = pow(g, private, p)
    send_json(conn, {"opcode": 1, "type": "DH", "public": public, "parameter": {"p": p, "g": g}})

    # 3. Alice가 보낸 오류 메시지 출력 (opcode 3 -> serve()가 "Alice가 보낸 오류: ..." 출력)
    msg = expect(conn, 3)
    print("Alice가 오류를 보내지 않음:", msg)


if __name__ == "__main__":
    args = bob_args(5554, extra=lambda parser: parser.add_argument(
        "-f", "--fault", choices=["random", "prime", "generator"], default="random"))
    serve(args.port, lambda conn: handle(conn, args.fault))
