"""Protocol IV - Alice (PPT 12~13): Protocol III의 Alice와 같은 검증 (p 소수 판정 -> g 생성원 검증).
테스트 서버는 연결마다 잘못된 p 또는 g를 랜덤으로 보내므로,
IV-I (incorrect prime number) 과 IV-II (incorrect generator) 가 각각 한 번씩 나올 때까지 다시 접속한다.

실행: python3 protocol4/alice.py                  (테스트 서버 10.41.12.51:5554)
      python3 protocol4/alice.py -a 127.0.0.1     (로컬 Bob)
"""
import os
import sys
import time
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용

from crypto_utils import alice_args, load_protocol, run_alice

MAX_TRIES = 20
LABELS = {"prime": "IV-I  incorrect prime number", "generator": "IV-II incorrect generator"}


def run_until_both(addr, port, message):
    """IV-I, IV-II가 각각 한 번씩 나올 때까지 접속을 반복한다."""
    protocol3_alice = load_protocol("protocol3", "alice")
    seen = []
    for attempt in range(1, MAX_TRIES + 1):
        print("\n########## 시도 {} (확인: {})".format(attempt, ", ".join(seen) or "없음"))
        result = []
        run_alice(addr, port, lambda conn: result.append(protocol3_alice.handle(conn, message)))
        error = result[0] if result else None
        if error in LABELS and error not in seen:
            seen.append(error)
            print(">>> {} 확인".format(LABELS[error]))
        if len(seen) == 2:
            break
        time.sleep(0.3)

    print("\n========== Protocol IV 결과")
    for error, label in LABELS.items():
        print("  {} : {}".format(label, "확인" if error in seen else "못 봄"))
    if len(seen) < 2:
        print("  ({}번 시도 안에 두 오류가 모두 나오지 않음)".format(MAX_TRIES))


if __name__ == "__main__":
    args = alice_args(5554, "world")
    run_until_both(args.addr, args.port, args.message)
