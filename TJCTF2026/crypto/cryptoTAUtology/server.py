#!/usr/local/bin/python3
import os
import re
import signal
import sys

FLAG_PATH = "flag.txt"
MAX_QUERIES = 1200
REGEX_TIMEOUT = 0.20
MAX_REGEX_LEN = 200


class RegexTimeout(Exception):
    pass


def main():
    def handle_timeout(signum, frame):
        raise RegexTimeout

    signal.signal(signal.SIGALRM, handle_timeout)

    flag_path = os.path.join(os.path.dirname(__file__), FLAG_PATH)
    with open(flag_path, "rb") as fh:
        flag = fh.read().strip().decode("utf-8", errors="strict")

    print("=== TAUtology regex validator ===")
    print("we validate regexes against a secret string...")
    print()
    print(f"limits: {MAX_QUERIES} queries, {REGEX_TIMEOUT:.2f}s per regex")

    queries = 0
    while queries < MAX_QUERIES:
        sys.stdout.write("regex> ")
        sys.stdout.flush()
        line = sys.stdin.readline().rstrip("\n").strip()

        if not line or line.lower() == "q":
            print("bye.")
            return
        if len(line) > MAX_REGEX_LEN:
            print("regex too long")
            continue

        try:
            signal.setitimer(signal.ITIMER_REAL, REGEX_TIMEOUT)
            re.match(line, flag, flags=re.DOTALL)
        except RegexTimeout:
            pass
        except re.error:
            print("invalid regex")
            continue
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        print("ok")
        queries += 1

    print("\nyou are out of queries. bye!")


if __name__ == "__main__":
    main()
