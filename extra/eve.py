"""추가 과제 - Eve (PPT 19~21): Alice와 Bob 사이의 메시지를 엿듣고(수동 공격) 평문을 복원한다.
숫자가 작아서(400~500) 가능한 공격:
  Protocol II : n을 인수분해 -> d 계산 -> AES 키 복원
  Protocol III: g^x = B (mod p)인 x를 전부 대입해서 찾음 -> 공유 비밀 복원

실행 1) 도청 기록 해독
  python3 extra/eve.py                                (extra/logs/ 의 기록 전부)
  python3 extra/eve.py extra/logs/adv_protocol_two.log

실행 2) 실시간 도청: Alice -> Eve -> Bob 사이에서 메시지를 그대로 전달하면서 해독
  python3 extra/eve.py --live --bob-port 5552         (Eve: 포트 5560, Bob = 테스트 서버 10.41.12.51:5552)
  python3 alice.py 2 -a 127.0.0.1 -p 5560             (Alice는 Bob 대신 Eve에 접속)
  --bob-addr 127.0.0.1 --bob-port 5555 처럼 주면 로컬 Bob을 대상으로 도청
  --save <파일> 을 주면 엿들은 메시지를 extra/logs 와 같은 형식으로 저장
"""
import argparse
import glob
import json
import os
import socket
import sys
import threading
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용

from crypto_utils import TEST_SERVER, aes_decrypt, dh_secret_to_aes_key, prime_factors, to_int


class Eve:
    """메시지를 하나씩 관찰하면서 알아낸 정보로 AES 키를 복원한다 (메시지는 절대 바꾸지 않음)."""

    def __init__(self):
        self.key = None

    def observe(self, msg):
        opcode, kind = msg.get("opcode"), msg.get("type")

        # --- Protocol II: RSA ---
        if opcode == 1 and kind == "RSA":
            self.e, self.n = to_int(msg["public"]), to_int(msg["parameter"]["n"])
            factors = prime_factors(self.n)                          # n = p * q 인수분해
            if len(factors) != 2:
                print("  [Eve] n =", self.n, "을 두 소수로 인수분해 못 함:", factors)
                return
            p, q = factors
            self.d = pow(self.e, -1, (p - 1) * (q - 1))
            print("  [Eve] n =", self.n, "=", p, "x", q, "-> 개인키 d =", self.d)
        elif opcode == 2 and kind == "RSA":
            self.key = bytes(pow(c, self.d, self.n) for c in msg["encrypted_key"])
            print("  [Eve] AES 키 복원:", self.key.hex())

        # --- Protocol III: DH ---
        elif opcode == 1 and kind == "DH" and "parameter" in msg:
            self.p, self.g = to_int(msg["parameter"]["p"]), to_int(msg["parameter"]["g"])
            bob_public = to_int(msg["public"])
            self.x = next((x for x in range(self.p) if pow(self.g, x, self.p) == bob_public), None)  # 이산 로그 전수 탐색
            if self.x is None:
                print("  [Eve] g^x = {} (mod {})인 x 없음".format(bob_public, self.p))
            else:
                print("  [Eve] g^x = Bob 공개키 를 만족하는 x =", self.x)
        elif opcode == 1 and kind == "DH":
            if getattr(self, "x", None) is None:
                return
            secret = pow(to_int(msg["public"]), self.x, self.p)
            self.key = dh_secret_to_aes_key(secret)
            print("  [Eve] 공유 비밀 =", secret, "-> AES 키 =", self.key.hex())

        # --- 해독 ---
        elif opcode == 2 and kind == "AES":
            if self.key is None:
                print("  [Eve] 아직 키를 모름")
            else:
                print("  [Eve] 해독한 메시지:", aes_decrypt(self.key, msg["encryption"]))
        elif opcode == 3:
            print("  [Eve] 오류 메시지 관찰:", msg.get("error"))


# ===================== 1) 도청 기록 해독 =====================
def attack_log(path):
    eve = Eve()
    for line in open(path):
        if line.strip():
            eve.observe(json.loads(line))


# ===================== 2) 실시간 도청 (중간에서 전달) =====================
def relay(src, dst, direction, eve, lock, save):
    """src에서 받은 바이트를 그대로 dst로 보내고, 완성된 JSON마다 Eve가 관찰한다."""
    decoder, buffer = json.JSONDecoder(), ""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)                               # 먼저 그대로 전달 (수동 공격: 변조 없음)
            buffer += data.decode(errors="replace")
            while buffer.strip():
                buffer = buffer.lstrip()
                try:
                    msg, end = decoder.raw_decode(buffer)
                except json.JSONDecodeError:
                    break                                   # 아직 덜 옴 -> 더 받기
                buffer = buffer[end:]
                with lock:
                    print(direction, json.dumps(msg))
                    if save:
                        save.write(json.dumps(msg) + "\n")
                        save.flush()
                    try:
                        eve.observe(msg)
                    except Exception as e:
                        print("  [Eve] 분석 실패:", type(e).__name__, e)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)                    # 한쪽이 끝나면 상대에게도 알림
        except OSError:
            pass


def live(port, bob_addr, bob_port, save_path):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen()
    print("Eve is listening on port {} -> Bob {}:{} (Ctrl+C로 종료)".format(port, bob_addr, bob_port))
    save = open(save_path, "a") if save_path else None
    try:
        while True:
            alice, addr = server.accept()
            print("\n=== Alice connected:", addr)
            try:
                bob = socket.create_connection((bob_addr, bob_port), timeout=15)
                bob.settimeout(None)
            except OSError as e:
                print("[Error] Bob에 접속 실패:", e)
                alice.close()
                continue
            eve, lock = Eve(), threading.Lock()
            threads = [threading.Thread(target=relay, args=(alice, bob, "Alice -> Bob:", eve, lock, save)),
                       threading.Thread(target=relay, args=(bob, alice, "Bob -> Alice:", eve, lock, save))]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            alice.close()
            bob.close()
            print("=== 연결 종료")
    except KeyboardInterrupt:
        print("\nEve 종료")
    finally:
        server.close()
        if save:
            save.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("logs", nargs="*", help="해독할 도청 기록 (생략 시 extra/logs/*.log)")
    parser.add_argument("--live", action="store_true", help="실시간 도청 모드")
    parser.add_argument("-p", "--port", type=int, default=5560, help="Eve가 열 포트 (실시간)")
    parser.add_argument("--bob-addr", default=TEST_SERVER, help="진짜 Bob 주소 (실시간)")
    parser.add_argument("--bob-port", type=int, default=5552, help="진짜 Bob 포트 (실시간)")
    parser.add_argument("--save", help="엿들은 메시지를 저장할 파일 (실시간)")
    args = parser.parse_args()

    if args.live:
        live(args.port, args.bob_addr, args.bob_port, args.save)
    else:
        logs = args.logs or sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "*.log")))
        for path in logs:
            print("\n=====", os.path.basename(path))
            attack_log(path)
