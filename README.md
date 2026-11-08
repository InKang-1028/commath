# Project 1-1: Asymmetric Cryptosystem (EL2001)

준비: `pip3 install pycryptodome` (슬라이드의 pycrypto 대신, 같은 `Crypto` 모듈 제공)

## 폴더 구조
```
project_1/
├── crypto_utils.py      공통 함수 (소수 판정, RSA, DH, AES, JSON 송수신)
├── protocol1/           Protocol I   (PPT 3)     RSA 키 생성·검증
│   ├── alice.py
│   └── bob.py
├── protocol2/           Protocol II  (PPT 4–7)   RSA로 AES 키 전달 → AES 대화
│   ├── alice.py
│   └── bob.py
├── protocol3/           Protocol III (PPT 8–11)  DH 키 교환 → AES 대화
│   ├── alice.py         (p 소수 판정 / g 생성원 검증 포함 = Protocol IV의 Alice)
│   └── bob.py
├── protocol4/           Protocol IV  (PPT 12–13) 잘못된 p, g 오류 처리
│   └── bob.py           일부러 잘못된 p 또는 g를 보내는 Bob
└── extra/
    ├── eve.py                   추가 과제: 엿들은 로그 해독
    └── benchmark_primality.py   소수 판정 3종 속도 비교
```

## 실행 (`project_1` 폴더에서, 터미널 2개)
| 프로토콜 | 터미널 1: Bob (먼저) | 터미널 2: Alice |
|---|---|---|
| I | `python3 protocol1/bob.py -p 5555` | `python3 protocol1/alice.py -a 127.0.0.1 -p 5555` |
| II | `python3 protocol2/bob.py -p 5555` | `python3 protocol2/alice.py -a 127.0.0.1 -p 5555` |
| III | `python3 protocol3/bob.py -p 5555` | `python3 protocol3/alice.py -a 127.0.0.1 -p 5555` |
| IV-I | `python3 protocol4/bob.py -p 5555 -f prime` | `python3 protocol3/alice.py -a 127.0.0.1 -p 5555` |
| IV-II | `python3 protocol4/bob.py -p 5555 -f generator` | `python3 protocol3/alice.py -a 127.0.0.1 -p 5555` |

- 메시지 바꾸기: `-m <메시지>` (기본값 Bob=hello, Alice=world)
- 추가 과제: `python3 extra/eve.py <로그파일>`
