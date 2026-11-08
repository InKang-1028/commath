import argparse
import logging
import random
import secrets
import socket
import threading

from alice import (
    is_generator,
    is_prime,
    receive_aes,
    receive_json,
    send_aes,
    send_json,
)


PRIMES = [number for number in range(400, 501) if is_prime(number)]


def rsa_session_key(sock, protocol):
    p, q = random.sample(PRIMES, 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)

    if protocol == "RSAKey":
        send_json(sock, {
            "opcode": 0,
            "type": "RSAKey",
            "public": e,
            "private": d,
            "parameter": {"p": p, "q": q},
        })
        return None

    send_json(sock, {
        "opcode": 1,
        "type": "RSA",
        "public": e,
        "parameter": {"n": n},
    })

    key_message = receive_json(sock)
    encrypted_key = key_message.get("encrypted_key")
    if (
        key_message.get("opcode") != 2
        or key_message.get("type") != "RSA"
        or not isinstance(encrypted_key, list)
        or len(encrypted_key) != 32
    ):
        raise ValueError("RSA로 암호화한 AES 키 정수 32개가 필요해.")

    return bytes(pow(value, d, n) for value in encrypted_key)


def dh_session_key(sock, dh_error):
    if dh_error == "prime":
        p, g = 400, 3
    else:
        p = random.choice(PRIMES)
        if dh_error == "generator":
            g = 4
        else:
            g = next(candidate for candidate in range(2, p)
                     if is_generator(candidate, p))

    bob_private = secrets.randbelow(p - 2) + 1
    bob_public = pow(g, bob_private, p)
    send_json(sock, {
        "opcode": 1,
        "type": "DH",
        "public": bob_public,
        "parameter": {"p": p, "g": g},
    })

    answer = receive_json(sock)
    if answer.get("opcode") == 3:
        print("Alice가 보낸 오류:", answer["error"], flush=True)
        return None

    if answer.get("opcode") != 1 or answer.get("type") != "DH":
        raise ValueError("Alice의 DH 공개값이 필요해.")

    alice_public = answer["public"]
    if not 1 <= alice_public < p:
        raise ValueError("Alice의 DH 공개값이 범위를 벗어났어.")

    shared_secret = pow(alice_public, bob_private, p)
    return shared_secret.to_bytes(2, byteorder="big") * 16


def handler(sock, message, dh_error):
    with sock:
        sock.settimeout(120)

        try:
            request = receive_json(sock)
            if request.get("opcode") != 0:
                return

            protocol = request.get("type")
            if protocol in ("RSAKey", "RSA"):
                session_key = rsa_session_key(sock, protocol)
            elif protocol == "DH":
                session_key = dh_session_key(sock, dh_error)
            else:
                return

            if session_key is not None:
                send_aes(sock, session_key, message)
                answer = receive_aes(sock, session_key)
                print("Alice가 보낸 답장:", answer, flush=True)
        except (OSError, EOFError, KeyError, TypeError, ValueError) as error:
            logging.warning("Bob: %s", error)


def run(addr, port, message, dh_error):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bob:
        bob.bind((addr, port))
        bob.listen(10)
        logging.info("Bob is listening on %s:%s", addr, port)

        while True:
            conn, info = bob.accept()
            logging.info("Bob accepts the connection from %s:%s", *info)
            thread = threading.Thread(
                target=handler, args=(conn, message, dh_error), daemon=True
            )
            thread.start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", default="0.0.0.0", help="Bob's address")
    parser.add_argument("-p", "--port", type=int, required=True, help="Bob's port")
    parser.add_argument("-l", "--log", default="INFO")
    parser.add_argument("--message", default="hello", help="Bob's first AES message")
    parser.add_argument("--dh-error", choices=("prime", "generator"))
    args = parser.parse_args()

    logging.basicConfig(level=args.log)
    try:
        run(args.addr, args.port, args.message, args.dh_error)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()