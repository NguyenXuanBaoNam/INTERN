import sys
import socket
import fcntl
import subprocess
from datetime import timedelta
from collections import defaultdict, deque
from urllib.parse import urlparse, unquote
import mimetypes
import os
from apachelogs import LogParser


access_log_path = "/var/log/nginx/access.log"
offset_file_path = "/var/tmp/antiddos.offset"
lock_file_path = "/var/tmp/antiddos.lock"  # tránh chạy chồng
window_seconds = 60
request_limit = 120
bot_auth_keywords = ("Googlebot", "bingbot", "facebookexternalhit", "Facebot")
ipset_name = "ddos_block"

_dns_cache_map = {}


# Nếu đã có tiến trình khác giữ lock, in thông báo và thoát.
def acquire_lock(path=lock_file_path):
    f = open(path, "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        f.write(str(os.getpid()))
        f.flush()
        return f
    except BlockingIOError:
        print("Một phiên AntiDdos.py khác đang chạy")
        sys.exit(0)


# kiểm tra xem có phải file text/html không
def is_static_asset(path: str) -> bool:
    parsed = urlparse(path)
    clean_path = unquote(parsed.path)
    mime_type, _ = mimetypes.guess_type(clean_path)
    if mime_type:
        if mime_type.startswith("text/html"):
            return False
        return True
    return False


# Chỉ cho qua Google/Bing/Facebook thật.
def is_verified_bot(client_ip: str, user_agent: str) -> bool:
    ua_l = user_agent.lower()
    google = "googlebot" in ua_l
    bing = "bingbot" in ua_l
    fb = ("facebookexternalhit" in ua_l) or ("facebot" in ua_l)
    if not (google or bing or fb):
        return False
    try:
        if client_ip in _dns_cache_map:
            host = _dns_cache_map[client_ip]["host"]
        else:
            host, _, _ = socket.gethostbyaddr(client_ip)
            _dns_cache_map[client_ip] = {"host": host}
    except Exception:
        return False
    host_l = host.lower()
    if google and not (host_l.endswith(".googlebot.com") or host_l.endswith(".google.com")):
        return False
    if bing and not host_l.endswith(".search.msn.com"):
        return False
    if fb and not host_l.endswith(".facebook.com"):
        return False
    try:
        if "addrs" not in _dns_cache_map[client_ip]:
            infos = socket.getaddrinfo(host, None)
            addrs = {ai[4][0] for ai in infos}
            _dns_cache_map[client_ip]["addrs"] = addrs
        else:
            addrs = _dns_cache_map[client_ip]["addrs"]
        return client_ip in addrs
    except Exception:
        return False


# chỉ xử lý log mới
def read_new_lines(log_path: str, offset_path: str):
    # Đọc offset cũ (nếu có)
    try:
        with open(offset_path, "r") as f:
            prev_off = int(f.read().strip() or "0")
    except Exception:
        prev_off = 0
    try:
        with open(log_path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            start = prev_off if 0 <= prev_off <= size else 0
            f.seek(start)
            if start > 0:
                f.readline()
            while True:
                line = f.readline()
                if not line:
                    break
                yield line.decode("utf-8", "ignore")

            new_off = f.tell()
    except FileNotFoundError:
        return
    try:
        with open(offset_path, "w") as f:
            f.write(str(new_off))
    except Exception:
        pass


def add_ip_to_ipset(ip_address: str):
    subprocess.run(
        ["ipset", "add", ipset_name, ip_address, "-exist"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def main():
    lock_handle = acquire_lock()
    parser = LogParser('%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"')
    timestamps_by_ip = defaultdict(lambda: deque())
    peak_requests_by_ip = defaultdict(int)
    total_lines = 0
    for line in read_new_lines(access_log_path, offset_file_path):
        total_lines += 1
        try:
            log = parser.parse(line)
        except Exception:
            continue
        try:
            # chỉ tính GET
            if not log.request_line or not log.request_line.startswith("GET"):
                continue
            # bỏ bot thật
            user_agent = log.headers_in.get("User-Agent", "")
            if any(kw in user_agent for kw in bot_auth_keywords):
                client_ip = log.remote_host
                if is_verified_bot(client_ip, user_agent):
                    continue
            # bỏ file tĩnh
            parts = log.request_line.split()
            if len(parts) < 2:
                continue
            path = parts[1]
            if is_static_asset(path):
                continue
            client_ip = log.remote_host
            request_time = log.request_time
            dq = timestamps_by_ip[client_ip]
            dq.append(request_time)
            window_start = request_time - timedelta(seconds=window_seconds)
            while dq and dq[0] <= window_start:
                dq.popleft()
            if len(dq) > peak_requests_by_ip[client_ip]:
                peak_requests_by_ip[client_ip] = len(dq)
        except Exception:
            continue
    offenders = [(client_ip, peak) for client_ip, peak in peak_requests_by_ip.items() if peak > request_limit]
    if offenders:
        print("IP vi phạm (req/60s):")
        for client_ip, peak in sorted(offenders, key=lambda x: -x[1]):
            print(f"{client_ip} : {peak} req/60s")
            add_ip_to_ipset(client_ip)
    else:
        print("Không có IP vi phạm.")
    print(f"Đã đọc {total_lines} dòng mới")
    lock_handle.close()


main()
