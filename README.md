# Project 1-1: Asymmetric Cryptosystem (EL2001)

> 구현 내용, 프로토콜별 메시지 흐름과 수학적 근거, 검증 결과: [HOW_IT_WORKS.md](HOW_IT_WORKS.md)

## 준비 (`project_1` 폴더에서)
```bash
source venv.sh      # 처음엔 .venv 생성 + pycryptodome 설치, 이후엔 활성화만
```
(슬라이드의 pycrypto 대신 pycryptodome 사용 — 같은 `Crypto` 모듈 제공. 끄기: `deactivate`)

## 폴더 구조
```
project_1/
├── venv.sh              가상환경 생성/활성화 (source로 실행)
├── alice.py             통합 Alice: python3 alice.py <1~4>
├── bob.py               통합 Bob: 포트 하나(5555)에서 요청 type(RSAKey/RSA/DH)을 보고 처리
├── crypto_utils.py      공통 함수 (소수 판정, RSA, DH, AES, JSON 송수신, 서버/클라이언트 실행)
├── protocol1/           Protocol I   (PPT 3)     RSA 키 생성·검증
├── protocol2/           Protocol II  (PPT 4–7)   RSA로 AES 키 전달 → AES 대화
├── protocol3/           Protocol III (PPT 8–11)  DH 키 교환 → AES 대화 (p, g 검증 포함)
├── protocol4/           Protocol IV  (PPT 12–13) 잘못된 p, g 오류 처리
│   ├── alice.py         = protocol3의 Alice (기본 포트만 5554)
│   └── bob.py           일부러 잘못된 p 또는 g를 보내는 Bob
└── extra/
    ├── eve.py                   추가 과제: 엿들은 로그 해독
    ├── logs/                    공식 스켈레톤 저장소의 도청 로그
    └── benchmark_primality.py   소수 판정 3종 속도 비교
```

## 실행 — 파일 하나씩, 인자 없이
기본값: Alice는 **테스트 서버 10.41.12.51** (VPN 필요), 포트는 프로토콜 번호에 맞춤.

| 프로토콜 | 포트 | 테스트 서버에 접속 (Alice) | 내 Bob 띄우기 |
|---|---|---|---|
| I   | 5551 | `python3 protocol1/alice.py` | `python3 protocol1/bob.py` |
| II  | 5552 | `python3 protocol2/alice.py` | `python3 protocol2/bob.py` |
| III | 5553 | `python3 protocol3/alice.py` | `python3 protocol3/bob.py` |
| IV  | 5554 | `python3 protocol4/alice.py` | `python3 protocol4/bob.py` (prime/generator 오류 랜덤) |
| Eve | – | `python3 extra/eve.py` (logs/ 전부 해독) | |
| 벤치마크 | – | `python3 extra/benchmark_primality.py` | |

## 통합 실행 — 파일 2개로 전부
통합 파일은 protocolN/ 의 코드를 그대로 불러 쓴다 (코드 중복 없음).

| 역할 | 명령 |
|---|---|
| Alice | `python3 alice.py 1` / `2` / `3` / `4` (테스트 서버, 포트 5551~5554 자동) |
| Bob (정상) | `python3 bob.py` (포트 5555, RSAKey·RSA·DH 모두 받음) |
| Bob (Protocol IV) | `python3 bob.py --dh-error random` (또는 `prime` / `generator`) — RSA 요청은 정상 처리 |
| 로컬 테스트 | `python3 alice.py 3 -a 127.0.0.1 -p 5555` |

옵션
- 로컬에서 테스트: 터미널 1에서 Bob 실행 → 터미널 2에서 `python3 protocolN/alice.py -a 127.0.0.1`
- 다른 주소/포트: `-a <주소> -p <포트>`
- 메시지 바꾸기 (II, III): `-m <메시지>` (기본값 Bob=hello, Alice=world)
- Protocol IV Bob 오류 고정: `-f prime` 또는 `-f generator`
- Bob은 연결 하나에서 오류가 나도 종료되지 않고 다음 연결을 기다림 (끄기: Ctrl+C)
