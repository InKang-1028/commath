"""통합 Alice: 프로토콜 번호만 골라서 실행한다 (실제 코드는 protocolN/alice.py).
실행: python3 alice.py 1                  Protocol I   -> 테스트 서버 10.41.12.51:5551
      python3 alice.py 2 -m world         Protocol II  -> :5552
      python3 alice.py 3                  Protocol III -> :5553
      python3 alice.py 4                  Protocol IV  -> :5554
      python3 alice.py 3 -a 127.0.0.1 -p 5555     (로컬 통합 Bob에 접속)
"""
import argparse

from crypto_utils import TEST_SERVER, load_protocol, run_alice

parser = argparse.ArgumentParser()
parser.add_argument("protocol", type=int, choices=[1, 2, 3, 4], help="프로토콜 번호")
parser.add_argument("-a", "--addr", default=TEST_SERVER, help="Bob 주소 (기본: 테스트 서버)")
parser.add_argument("-p", "--port", type=int, help="Bob 포트 (기본: 5550 + 프로토콜 번호)")
parser.add_argument("-m", "--message", default="world", help="Bob에게 보낼 메시지 (II, III)")
parser.add_argument("-l", "--log", default="INFO", help="로그 레벨 (스켈레톤 호환용)")
args = parser.parse_args()
port = args.port or 5550 + args.protocol

if args.protocol == 1:
    handle = load_protocol("protocol1", "alice").handle
elif args.protocol == 2:
    p2 = load_protocol("protocol2", "alice")
    handle = lambda conn: p2.handle(conn, args.message)
else:                                   # III, IV: 같은 Alice (p, g 검증 포함)
    p3 = load_protocol("protocol3", "alice")
    handle = lambda conn: p3.handle(conn, args.message)

run_alice(args.addr, port, handle)
