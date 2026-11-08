"""Protocol IV - Alice (PPT 12~13): Protocol III의 Alice와 똑같다 (p 소수 판정, g 생성원 검증 포함).
기본 포트만 5554로 바꿔서 protocol3/alice.py를 실행한다.
실행: python3 protocol4/alice.py                  (테스트 서버 10.41.12.51:5554)
      python3 protocol4/alice.py -a 127.0.0.1
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용

from crypto_utils import load_protocol

if __name__ == "__main__":
    load_protocol("protocol3", "alice").main(default_port=5554)
