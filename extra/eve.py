"""추가 과제 - Eve (PPT 20~21): 엿들은 통신 로그만으로 메시지를 해독한다.
숫자가 작아서(400~500) 가능한 공격:
  Protocol II : n을 인수분해 -> d 계산 -> AES 키 복원
  Protocol III: g^x = A (mod p)인 x를 전부 대입해서 찾음 -> 공유 비밀 복원

실행: python3 extra/eve.py                              (extra/logs/ 의 로그 전부 해독)
      python3 extra/eve.py extra/logs/adv_protocol_two.log
"""
import glob
import json
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용

from crypto_utils import aes_decrypt, dh_secret_to_aes_key, prime_factors


def attack(log_path):
    key = None
    for line in open(log_path):
        if not line.strip():
            continue
        msg = json.loads(line)

        # --- Protocol II: RSA ---
        if msg["opcode"] == 1 and msg["type"] == "RSA":
            e, n = msg["public"], msg["parameter"]["n"]
            p, q = prime_factors(n)                          # n = p * q 인수분해
            d = pow(e, -1, (p - 1) * (q - 1))
            print("n =", n, "=", p, "x", q, "-> 개인키 d =", d)
        elif msg["opcode"] == 2 and msg["type"] == "RSA":
            key = bytes(pow(c, d, n) for c in msg["encrypted_key"])
            print("AES 키 복원:", key.hex())

        # --- Protocol III: DH ---
        elif msg["opcode"] == 1 and msg["type"] == "DH" and "parameter" in msg:
            bob_public, p, g = msg["public"], msg["parameter"]["p"], msg["parameter"]["g"]
        elif msg["opcode"] == 1 and msg["type"] == "DH":
            x = next(x for x in range(p) if pow(g, x, p) == bob_public)   # 이산 로그 전수 탐색
            secret = pow(msg["public"], x, p)
            key = dh_secret_to_aes_key(secret)
            print("Bob의 개인키 =", x, "-> 공유 비밀 =", secret)

        # --- 해독 ---
        elif msg["opcode"] == 2 and msg["type"] == "AES":
            print("해독한 메시지:", aes_decrypt(key, msg["encryption"]))


if __name__ == "__main__":
    logs = sys.argv[1:] or sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "*.log")))
    for path in logs:
        print("\n=====", os.path.basename(path))
        attack(path)
