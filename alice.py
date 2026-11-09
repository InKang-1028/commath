"""통합 Alice: 프로토콜 번호만 골라서 실행한다 (실제 코드는 protocolN/alice.py).
실행: python3 alice.py                    번호를 물어봄 (1~4)
      python3 alice.py 1                  Protocol I   -> 테스트 서버 10.41.12.51:5551
      python3 alice.py 2                  Protocol II  -> :5552  (보낼 메시지는 실행 중에 물어봄)
      python3 alice.py 3                  Protocol III -> :5553
      python3 alice.py 4                  Protocol IV  -> :5554 (IV-I, IV-II 각각 나올 때까지 반복)
      python3 alice.py 3 -a 127.0.0.1 -p 5555     (로컬 통합 Bob에 접속)
포트는 아래 PORTS에서 읽는다 (-p를 주면 그게 우선).
"""
import argparse
import sys

from crypto_utils import TEST_SERVER, load_protocol, parse_with_range, run_alice

# Bob 포트. 포트가 바뀌면 여기만 고치면 된다.
PORTS = {1: 5551, 2: 5552, 3: 5553, 4: 5554}

MENU = [(1, "I", "RSA 키 생성"), (2, "II", "RSA로 AES 키 전달"), (3, "III", "DH 키 교환"), (4, "IV", "DH 오류 처리")]

parser = argparse.ArgumentParser()
parser.add_argument("protocol", type=int, nargs="?", choices=[1, 2, 3, 4], help="프로토콜 번호 (생략하면 물어봄)")
parser.add_argument("-a", "--addr", default=TEST_SERVER, help="Bob 주소 (기본: 테스트 서버)")
parser.add_argument("-p", "--port", type=int, help="Bob 포트 (기본: PORTS)")
parser.add_argument("-l", "--log", default="INFO", help="로그 레벨 (스켈레톤 호환용)")
args = parse_with_range(parser)

# 번호를 안 주면 메뉴에서 고른다
while args.protocol is None:
    for number, roman, name in MENU:
        print("  {}. Protocol {:<3} {}  (포트 {})".format(number, roman, name, PORTS[number]))
    try:
        answer = input("실행할 프로토콜 번호 (1~4): ").strip()
    except (EOFError, KeyboardInterrupt):
        sys.exit("\n종료. 번호를 직접 줄 수도 있음: python3 alice.py <1~4>")
    if answer in ("1", "2", "3", "4"):
        args.protocol = int(answer)

port = args.port or PORTS[args.protocol]

# 보낼 메시지를 물어본다 (I은 메시지를 안 씀). 그냥 엔터면 world
message = None
if args.protocol != 1:
    try:
        message = input("Bob에게 보낼 메시지 (엔터: world): ").strip() or "world"
    except (EOFError, KeyboardInterrupt):
        sys.exit("\n종료.")

if args.protocol == 4:                  # IV-I, IV-II가 각각 나올 때까지 반복
    load_protocol("protocol4", "alice").run_until_both(args.addr, port, message)
    sys.exit()

if args.protocol == 1:
    handle = load_protocol("protocol1", "alice").handle
elif args.protocol == 2:
    p2 = load_protocol("protocol2", "alice")
    handle = lambda conn: p2.handle(conn, message)
else:                                   # III (p, g 검증 포함)
    p3 = load_protocol("protocol3", "alice")
    handle = lambda conn: p3.handle(conn, message)

run_alice(args.addr, port, handle)
