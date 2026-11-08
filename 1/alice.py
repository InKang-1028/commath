import argparse
import base64
import json
import logging
import secrets
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def is_prime(number):
    if number < 2:
        return False

    divisor = 2
    while divisor * divisor <= number:
        if number % divisor == 0:
            return False
        divisor += 1

    return True


def is_generator(g, p):
    if not 1 < g < p:
        return False

    residues = {pow(g, exponent, p) for exponent in range(1, p)}
    return len(residues) == p - 1


def send_json(sock, message):
    sock.sendall(json.dumps(message).encode("ascii"))


def receive_json(sock):
    data = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("상대가 JSON 메시지를 보내기 전에 연결을 닫았어.")
        data.extend(chunk)

        try:
            return json.loads(data)
        except json.JSONDecodeError:
            if len(data) >= 1_048_576:
                raise ValueError("JSON 메시지가 너무 크거나 형식이 잘못됐어.")


def send_aes(sock, session_key, message):
    cipher = AES.new(session_key, AES.MODE_ECB)
    padded = pad(message.encode("utf-8"), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    send_json(sock, {
        "opcode": 2,
        "type": "AES",
        "encryption": base64.b64encode(ciphertext).decode("ascii"),
    })


def receive_aes(sock, session_key):
    message = receive_json(sock)
    if message.get("opcode") != 2 or message.get("type") != "AES":
        raise ValueError("AES 메시지가 필요해.")

    ciphertext = base64.b64decode(message["encryption"], validate=True)
    cipher = AES.new(session_key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode("utf-8")


def verify_rsa_key(response):
    p = response["parameter"]["p"]
    q = response["parameter"]["q"]
    e = response["public"]
    d = response["private"]
    phi = (p - 1) * (q - 1)

    p_prime = is_prime(p)
    q_prime = is_prime(q)
    print(f"p = {p}, 소수인가? {p_prime}")
    print(f"q = {q}, 소수인가? {q_prime}")

    primes_valid = p_prime and q_prime and p != q
    primes_valid = primes_valid and 400 <= p <= 500 and 400 <= q <= 500
    keys_valid = primes_valid and e > 1 and d > 0 and (e * d) % phi == 1

    print(f"e = {e}, d = {d}, phi = {phi}")
    print(f"RSA 키 쌍이 올바른가? {keys_valid}")


def rsa_session_key(conn, response):
    e = response["public"]
    n = response["parameter"]["n"]
    print(f"RSA 공개키를 받았어. e = {e}, n = {n}")

    session_key = secrets.token_bytes(32)
    send_json(conn, {
        "opcode": 2,
        "type": "RSA",
        "encrypted_key": [pow(byte, e, n) for byte in session_key],
    })
    return session_key


def dh_session_key(conn, response):
    p = response["parameter"]["p"]
    g = response["parameter"]["g"]

    if not (400 <= p <= 500 and is_prime(p)):
        error = "incorrect prime number"
    elif not is_generator(g, p):
        error = "incorrect generator"
    else:
        bob_public = response["public"]
        if not 1 <= bob_public < p:
            raise ValueError("Bob의 DH 공개값이 범위를 벗어났어.")

        alice_private = secrets.randbelow(p - 2) + 1
        alice_public = pow(g, alice_private, p)
        shared_secret = pow(bob_public, alice_private, p)

        send_json(conn, {"opcode": 1, "type": "DH", "public": alice_public})
        print(f"DH 키 교환 완료. p = {p}, g = {g}")
        return shared_secret.to_bytes(2, byteorder="big") * 16

    send_json(conn, {"opcode": 3, "error": error})
    print(error)
    return None


def run(addr, port, protocol=1):
    request_types = {1: "RSAKey", 2: "RSA", 3: "DH", 4: "DH"}
    request_type = request_types[protocol]

    with socket.create_connection((addr, port), timeout=15) as conn:
        logging.info("Alice is connected to %s:%s", addr, port)
        send_json(conn, {"opcode": 0, "type": request_type})
        response = receive_json(conn)
        print("Bob의 응답:", json.dumps(response))

        if protocol == 1:
            verify_rsa_key(response)
            return

        if protocol == 2:
            session_key = rsa_session_key(conn, response)
        else:
            session_key = dh_session_key(conn, response)
            if session_key is None:
                return

        print("Bob이 보낸 메시지:", receive_aes(conn, session_key))
        message = input("Bob에게 보낼 답장: ")
        send_aes(conn, session_key, message)
        print("AES로 암호화한 답장을 보냈어.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", required=True, help="Bob's address")
    parser.add_argument("-p", "--port", type=int, required=True, help="Bob's port")
    parser.add_argument("-l", "--log", default="INFO")
    parser.add_argument("--protocol", type=int, choices=(1, 2, 3, 4), default=1)
    args = parser.parse_args()

    logging.basicConfig(level=args.log)
    try:
        run(args.addr, args.port, args.protocol)
    except (OSError, EOFError, KeyError, TypeError, ValueError) as error:
        parser.exit(1, f"Alice: {error}\n")


if __name__ == "__main__":
    main()