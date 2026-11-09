"""통합 Eve (PPT 19~21): Alice와 Bob 사이의 메시지를 엿듣고(수동 공격) 평문을 복원한다.
숫자가 작아서(400~500) 가능한 공격:
  Protocol II : n을 인수분해 -> d 계산 -> AES 키 복원
  Protocol III: g^x = B (mod p)인 x를 전부 대입해서 찾음 -> 공유 비밀 복원

실행: python3 eve.py                                  extra/logs/ 의 도청 기록 전부 해독
      python3 eve.py extra/logs/adv_protocol_two.log   특정 기록만 해독

선택 기능 (실시간 도청): Alice -> Eve -> Bob 으로 메시지를 그대로 전달하면서 해독
      python3 eve.py --live [2|3]       번호를 안 주면 물어봄. Eve는 포트 5560에서 Alice를 기다림
      python3 eve.py --live 3 -a 127.0.0.1 -p 5555    (로컬 통합 Bob으로 중계)
      그리고 다른 터미널에서 python3 alice.py <번호> (Eve가 떠 있으면 Alice가 알아서 Eve를 거침)
      --save <파일> 을 주면 엿들은 메시지를 extra/logs 와 같은 형식으로 저장
주소와 포트는 아래 SERVER, PORTS, EVE_PORT에서 읽는다 (-a, -p, -e를 주면 그게 우선).
"""
import argparse
import glob
import json
import os
import socket
import sys
import threading

from crypto_utils import aes_decrypt, dh_secret_to_aes_key, prime_factors, to_int

# 진짜 Bob(테스트 서버) 주소와 포트 (alice.py의 SERVER, PORTS와 같게). 바뀌면 여기만 고치면 된다.
SERVER = "10.41.12.51"
PORTS = {1: 5551, 2: 5552, 3: 5553, 4: 5554}
EVE_PORT = 5560     # Eve가 Alice를 기다리는 포트

MENU = [(1, "I", "RSA 키 생성"), (2, "II", "RSA로 AES 키 전달"), (3, "III", "DH 키 교환"), (4, "IV", "DH 오류 처리")]


class Eve:
    """메시지를 하나씩 관찰하면서 알아낸 정보로 AES 키를 복원한다 (메시지는 절대 바꾸지 않음)."""

    def __init__(self):
        self.key = None

    def observe(self, msg, direction=""):
        opcode, kind = msg.get("opcode"), msg.get("type")

        # --- Protocol II: RSA ---
        if opcode == 1 and kind == "RSA":
            param = msg["parameter"]
            self.e = to_int(msg["public"])
            if "n" in param:                                         # 슬라이드 20 예시: n만 공개
                self.n = to_int(param["n"])
                factors = prime_factors(self.n)                      # n = p * q 인수분해
                if len(factors) != 2:
                    print("  [Eve] n =", self.n, "을 두 소수로 인수분해 못 함:", factors)
                    return
                p, q = factors
            else:                                                    # 슬라이드 15: p, q를 직접 보낸 경우
                p, q = to_int(param["p"]), to_int(param["q"])
                self.n = p * q
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
                who = " ({})".format(direction) if direction else ""
                print("  [Eve] 해독한 메시지{}:".format(who), aes_decrypt(self.key, msg["encryption"]))
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
                        eve.observe(msg, direction.rstrip(":"))
                    except Exception as e:
                        print("  [Eve] 분석 실패:", type(e).__name__, e)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)                    # 한쪽이 끝나면 상대에게도 알림
        except OSError:
            pass


def session(alice, addr, bob_addr, bob_port, save):
    """Alice 한 명의 연결을 Bob에게 중계한다 (연결마다 스레드)."""
    try:
        if not alice.recv(1, socket.MSG_PEEK):              # 아무것도 안 보내고 끊김 (Alice의 Eve 확인용 접속) -> 무시
            alice.close()
            return
    except OSError:
        alice.close()
        return
    print("\n=== Alice connected:", addr)
    try:
        bob = socket.create_connection((bob_addr, bob_port), timeout=15)
        bob.settimeout(None)
    except OSError as e:
        print("[Error] Bob에 접속 실패:", e)
        alice.close()
        return
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


def live(port, bob_addr, bob_port, save_path, protocol=None):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen()
    print("Eve is listening on port {} -> Bob {}:{} (Ctrl+C로 종료)".format(port, bob_addr, bob_port))
    print("Alice가 접속하길 기다리는 중. 다른 터미널에서 python3 alice.py 만 실행하면 자동으로 Eve를 거침 (직접 지정:")
    print("  python3 alice.py {} -a 127.0.0.1 -p {} )".format(protocol or "<1~4>", port))
    save = open(save_path, "a") if save_path else None
    try:
        while True:
            alice, addr = server.accept()
            threading.Thread(target=session, args=(alice, addr, bob_addr, bob_port, save), daemon=True).start()
    except KeyboardInterrupt:
        print("\nEve 종료")
    finally:
        server.close()
        if save:
            save.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("logs", nargs="*", help="해독할 도청 기록 (생략하면 extra/logs/*.log 전부)")
    parser.add_argument("--live", nargs="?", const=0, type=int, choices=[0, 1, 2, 3, 4], metavar="번호",
                        help="실시간 도청 (프로토콜 번호, 생략하면 물어봄)")
    parser.add_argument("-a", "--addr", default=SERVER, help="[live] 진짜 Bob 주소 (기본: 테스트 서버)")
    parser.add_argument("-p", "--port", type=int, help="[live] 진짜 Bob 포트 (기본: PORTS)")
    parser.add_argument("-e", "--eve-port", type=int, default=EVE_PORT, help="[live] Eve가 열 포트 (기본: EVE_PORT)")
    parser.add_argument("--save", help="[live] 엿들은 메시지를 저장할 파일")
    args = parser.parse_args()

    if args.live is None:                       # 기본: 도청 기록 해독
        logs = args.logs or sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "extra", "logs", "*.log")))
        for path in logs:
            print("\n=====", os.path.basename(path))
            attack_log(path)
        sys.exit()

    protocol = args.live or None
    while protocol is None:                     # 번호를 안 주면 메뉴에서 고른다
        for number, roman, name in MENU:
            print("  {}. Protocol {:<3} {}  (Bob 포트 {})".format(number, roman, name, PORTS[number]))
        try:
            answer = input("엿들을 프로토콜 번호 (1~4): ").strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit("\n종료. 번호를 직접 줄 수도 있음: python3 eve.py --live <1~4>")
        if answer in ("1", "2", "3", "4"):
            protocol = int(answer)

    live(args.eve_port, args.addr, args.port or PORTS[protocol], args.save, protocol)
