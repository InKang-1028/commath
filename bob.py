"""통합 Bob: 포트 하나로 모든 프로토콜을 받는다. Alice 요청의 "type"을 보고 해당 프로토콜로 처리.
  RSAKey -> Protocol I  /  RSA -> Protocol II  /  DH -> Protocol III (--dh-error 주면 Protocol IV)
실제 코드는 protocolN/bob.py 의 respond().

실행: python3 bob.py                         포트 5555, 정상 DH
      python3 bob.py --dh-error random       DH 요청에 잘못된 p 또는 g (Protocol IV)
      python3 bob.py --dh-error prime        (IV-I)   /   --dh-error generator  (IV-II)
"""
from crypto_utils import bob_args, expect, load_protocol, serve

p1 = load_protocol("protocol1", "bob")
p2 = load_protocol("protocol2", "bob")
p3 = load_protocol("protocol3", "bob")
p4 = load_protocol("protocol4", "bob")

args = bob_args(5555, "hello", extra=lambda parser: parser.add_argument(
    "--dh-error", choices=["random", "prime", "generator"], help="DH 요청에 일부러 잘못된 p/g 보내기"))


def handle(conn):
    # 1. Alice의 요청 받고 type으로 프로토콜 고르기
    request = expect(conn, 0)
    kind = request.get("type")
    if kind == "RSAKey":
        p1.respond(conn)
    elif kind == "RSA":
        p2.respond(conn, args.message)
    elif kind == "DH" and args.dh_error:
        p4.respond(conn, args.dh_error)
    elif kind == "DH":
        p3.respond(conn, args.message)
    else:
        raise ValueError("모르는 type: {}".format(kind))


serve(args.port, handle)
