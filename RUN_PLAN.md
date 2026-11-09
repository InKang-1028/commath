# 실행 계획

각 프로토콜과 추가 과제를 실행하는 순서와 예상 결과를 정리한다. 구현 설명은 [HOW_IT_WORKS.md](HOW_IT_WORKS.md), 명령 요약은 [README.md](README.md)를 참고한다.

---

## 0. 준비

```bash
git switch main && git pull origin main
cd project_1
source venv.sh          # 처음 실행 시 .venv 생성 및 pycryptodome 설치, 이후에는 활성화만 수행
```

- 테스트 서버(10.41.12.51)를 사용하려면 브라우저에서 **vpn.kentech.ac.kr** 에 로그인한다.
- `venv.sh` 는 반드시 `source` 로 실행한다. 종료는 `deactivate`.
- Windows PowerShell: `python -m venv .venv` → `.venv\Scripts\activate` → `pip install pycryptodome`

---

## 1. Protocol I — RSA 키 생성

| 항목 | 내용 |
|---|---|
| 터미널 | 1개 |
| 명령 | `python3 alice.py 1` (또는 `python3 protocol1/alice.py`) |
| 접속 대상 | 테스트 서버 5551 |

예상 출력
```
p = 443 -> 소수 판정: PASS
q = 457 -> 소수 판정: PASS
공개키 e = 145283 , n = 202451
개인키 d = 162011
RSA 키쌍: CORRECT
```

---

## 2. Protocol II — RSA를 이용한 AES 키 전달

| 항목 | 내용 |
|---|---|
| 터미널 | 1개 |
| 명령 | `python3 alice.py 2` (메시지 변경: `-m "보낼 메시지"`) |
| 접속 대상 | 테스트 서버 5552 |

예상 흐름
1. `encrypted_key` (정수 32개) 전송
2. `Bob이 보낸 메시지: hello`
3. Alice의 메시지(기본값 `world`)를 AES로 암호화하여 전송

---

## 3. Protocol III — Diffie-Hellman 키 교환

| 항목 | 내용 |
|---|---|
| 터미널 | 1개 |
| 명령 | `python3 alice.py 3` |
| 접속 대상 | 테스트 서버 5553 |

예상 출력
```
p = 419 -> 소수 판정: PASS
g = 391 -> 생성원 검증: PASS
공유 비밀 = 278 , AES 키 = 0116011601160116...
Bob이 보낸 메시지: hello
```

---

## 4. Protocol IV — DH 오류 처리

| 항목 | 내용 |
|---|---|
| 터미널 | 1개 |
| 명령 | `python3 alice.py 4` |
| 접속 대상 | 테스트 서버 5554 (오류 종류가 무작위이므로 두 경우가 모두 나올 때까지 반복 실행) |

예상 출력 (둘 중 하나)
```
p = 493 는 소수가 아님 -> 종료
[Sent]      {"opcode": 3, "error": "incorrect prime number"}
```
```
p = 433 -> 소수 판정: PASS
g = 154 는 생성원이 아님 -> 종료
[Sent]      {"opcode": 3, "error": "incorrect generator"}
```

---

## 5. 자체 Bob을 서버로 실행하는 경우

상대(평가용 Alice 등)가 우리 Bob에 접속하는 경우에 사용한다.

| 터미널 | 명령 | 설명 |
|---|---|---|
| 1 (Bob, 계속 실행) | `python3 bob.py` | 포트 5555에서 Protocol I, II, III 요청을 모두 처리 |
| | `python3 bob.py --dh-error random` | Protocol IV: DH 요청에 잘못된 p 또는 g 전송 (`prime` / `generator` 로 고정 가능) |
| | `python3 protocolN/bob.py` | 프로토콜별 포트(5551–5554)로 실행 |
| 2 (확인용 Alice) | `python3 alice.py 3 -a 127.0.0.1 -p 5555` | 로컬에서 동작 확인 |

- 다른 컴퓨터에서 접속하는 경우: 내 IP 주소(`ifconfig` / `ipconfig`)와 포트를 상대에게 알려 준다.
- 접속이 되지 않으면 방화벽에서 해당 포트를 허용한다.
- Bob 종료: Ctrl+C

Bob 화면 예상 출력
```
=== Alice connected: ('127.0.0.1', 40074)
공유 비밀 = 327 , AES 키 = 0147014701470147...
Alice가 보낸 메시지: world
```
Protocol IV 모드에서는 `Alice가 보낸 오류: incorrect prime number` 또는 `incorrect generator` 가 출력된다.

---

## 6. 추가 과제 — Eve

### 6.1 도청 기록 해독

| 항목 | 내용 |
|---|---|
| 터미널 | 1개 |
| 명령 | `python3 extra/eve.py` (특정 기록만: `python3 extra/eve.py extra/logs/adv_protocol_two.log`) |

예상 출력
```
===== adv_protocol_two.log
  [Eve] n = 194477 = 439 x 443 -> 개인키 d = 152669
  [Eve] AES 키 복원: 7046a907...
  [Eve] 해독한 메시지: mathematics
```

### 6.2 실시간 도청

| 터미널 | 명령 | 설명 |
|---|---|---|
| 1 (Eve) | `python3 extra/eve.py --live --bob-port 5552` | 포트 5560에서 Alice를 받아 테스트 서버 5552로 중계 (Protocol III은 `--bob-port 5553`) |
| 2 (Alice) | `python3 alice.py 2 -a 127.0.0.1 -p 5560` | Bob 대신 Eve에 접속 (Protocol III은 `alice.py 3`) |

- 로컬 Bob을 대상으로 할 경우: `--bob-addr 127.0.0.1 --bob-port 5555`
- 도청한 메시지 저장: `--save <파일>` (저장한 파일은 6.1 방식으로 다시 해독 가능)

예상 결과: Alice는 정상적으로 `hello` 를 수신하고, Eve 화면에는 다음이 출력된다.
```
  [Eve] n = 221777 = 463 x 479 -> 개인키 d = 41291
  [Eve] AES 키 복원: a34766d9...
  [Eve] 해독한 메시지: hello
  [Eve] 해독한 메시지: world
```

---

## 7. 소수 판정 알고리즘 비교

| 항목 | 내용 |
|---|---|
| 터미널 | 1개 |
| 명령 | `python3 extra/benchmark_primality.py` |

예상 출력: 구간별 시행 나눗셈, 페르마, 밀러-라빈의 소요 시간과 소수 개수 표, 그리고 카마이클 수 예시
```
Carmichael 561: trial=False, fermat(base 2)=True, miller-rabin=False
```

---

## 8. 권장 시연 순서

1. Protocol I
2. Protocol II
3. Protocol III
4. Protocol IV (두 가지 오류가 모두 나올 때까지)
5. 자체 Bob (필요한 경우)
6. Eve 도청 기록 해독 → 실시간 도청
7. 소수 판정 비교

---

## 9. 공통 옵션

| 옵션 | 대상 | 설명 |
|---|---|---|
| `-a`, `--addr` | Alice | 접속할 Bob 주소 (기본: 10.41.12.51) |
| | Bob | 바인드 주소 (기본: 0.0.0.0) |
| `-p`, `--port` | 공통 | 포트 (Alice 기본: 5550 + 프로토콜 번호, 통합 Bob 기본: 5555) |
| `-m`, `--message` | Protocol II, III | 보낼 메시지 (Alice 기본 `world`, Bob 기본 `hello`) |
| `-l`, `--log` | 공통 | 로그 레벨 (과제 기본 코드와의 호환용) |
| `--min`, `--max` | 공통 | 소수 범위 (기본 400, 500). Bob은 이 범위에서 난수로 고르고, Alice는 이 범위로 검증한다. 양쪽에 같은 값을 준다 |
| `--dh-error` | 통합 Bob | `random` / `prime` / `generator` |
| `-f`, `--fault` | `protocol4/bob.py` | `random` / `prime` / `generator` |

---

## 10. 문제 발생 시

| 증상 | 원인 및 조치 |
|---|---|
| `ModuleNotFoundError: No module named 'Crypto'` | 가상환경 미활성화 → `source venv.sh` |
| `[Error] TimeoutError` / 연결 거부 | VPN 로그인 확인, 테스트 서버가 열려 있는지 확인 후 재실행 |
| 자체 Bob에 외부 접속 불가 | 방화벽 포트 허용, IP 주소 확인 |
| Alice가 `INCORRECT` 또는 `incorrect prime number` 를 계속 출력 | Bob과 Alice의 `--min`/`--max` 값이 다름 → 양쪽 범위를 맞춘다 |
| `Address already in use` | 같은 포트의 Bob이 이미 실행 중 → 기존 Bob 종료 또는 `-p` 로 다른 포트 사용 |
