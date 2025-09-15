import sys
import re
from collections import Counter
from user_agents import parse


def classify_browser(ua: str) -> str:
    user_agent = parse(ua)
    return user_agent.browser.family


def split_ua(line: str):
    qs = re.findall(r'"([^"]*)"', line)
    return qs[-1] if qs else ""


def count_request(lines):
    c, tot = Counter(), 0
    for line in lines:
        ua = split_ua(line)
        if not ua:
            continue
        c[classify_browser(ua)] += 1
        tot += 1
    return c, tot


def print_table(counts: Counter, total: int):
    if total == 0:
        print("No request.")
        return
    items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    print(f"{'Browser':<30} {'Requests':>10} {'Share %':>9}")
    print(f"{'-'*20} {'-'*10:>10} {'-'*9:>9}")
    for name, cnt in items:
        pct = cnt * 100 / total
        print(f"{name:<30} {cnt:>10} {pct:>8.1f}%")
    print(f"{'-'*30} {'-'*10:>10} {'-'*9:>9}")
    print(f"{'Total':<30} {total:>10} {100.0:>8.1f}%\n")


def main():
    # đọc toàn bộ log từ stdin
    lines = (line.rstrip("\n") for line in sys.stdin)
    counts, total = count_request(lines)
    print_table(counts, total)


main()
