"""Compare elapsed time of three primality tests (trial division, Fermat, Miller-Rabin)."""

import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 상위 폴더의 crypto_utils.py 사용
import time

from crypto_utils import is_prime_fermat, is_prime_miller_rabin
from crypto_utils import is_prime as is_prime_trial

TESTS = [("Trial division", is_prime_trial), ("Fermat", is_prime_fermat), ("Miller-Rabin", is_prime_miller_rabin)]
RANGES = [("[400, 500]", range(400, 501)), ("[10^6, 10^6+2000]", range(10**6, 10**6 + 2001)),
          ("[10^12, 10^12+500]", range(10**12, 10**12 + 501))]


def main():
    print("{:<20} {:<16} {:>12} {:>8}".format("range", "test", "time (ms)", "#primes"))
    for rname, numbers in RANGES:
        reference = None
        for tname, test in TESTS:
            start = time.perf_counter()
            primes = [n for n in numbers if test(n)]
            elapsed = (time.perf_counter() - start) * 1000
            reference = reference or primes
            flag = "" if primes == reference else "  (differs from trial division!)"
            print("{:<20} {:<16} {:>12.3f} {:>8}{}".format(rname, tname, elapsed, len(primes), flag))
    # Carmichael numbers fool Fermat for every base coprime to n (here base 2), but not Miller-Rabin
    for c in (561, 1105, 1729):
        print("Carmichael {}: trial={}, fermat(base 2)={}, miller-rabin={}".format(
            c, is_prime_trial(c), pow(2, c - 1, c) == 1, is_prime_miller_rabin(c)))


if __name__ == "__main__":
    main()
