import sys
import re  # sys để đọc input, re để tách, xử lý chuỗi
from datetime import datetime

# dùng để bắt từng trường trong log
log_pattern = re.compile(
    # \S+: ăn (lưu) hết 1 chuỗi kí tự không có khoảng trắng
    # \s+: nuốt 1 kí tự là khoảng trắng
    r'^(?P<remote_address>\S+)\s+'
    r'(?P<forwarded_for>\S+)\s+'
    r'\[(?P<time_iso8601>[^\]]+)\]\s+'  # [^\]]+ bắt tất cả ký tự không phải dấu ]
    r'(?P<http_host>\S+)\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes_sent>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"\s+'
    r'(?P<gzip_ratio>\S+)\s+'
    r'(?P<request_length>\S+)\s+'
    r'(?P<request_time>\S+)\s*$',
    re.ASCII  # re.ASCII làm cho \d, \s, \w chỉ match ASCII
)


def select_ip(forwarded_for: str, remote_address: str) -> str:
    if forwarded_for and forwarded_for != '-' and forwarded_for.strip():
        return forwarded_for.split(',')[0].strip()
    else:
        return remote_address


def normalize_time(iso_time: str) -> str:
    try:  # nếu chuẩn hóa được
        time_clf = iso_time.replace('Z', '+00:00')
        dt = datetime.fromisoformat(time_clf)
        return dt.strftime("%d/%b/%Y:%H:%M:%S %z")
    except Exception:  # nếu không chuẩn hóa được
        return iso_time


def convert_log_entry(match_obj) -> str:
    ip = select_ip(match_obj['forwarded_for'], match_obj['remote_address'])
    log_time = normalize_time(match_obj['time_iso8601'])
    request = match_obj['request']
    status = match_obj['status']
    size = match_obj['bytes_sent']
    return f"{ip} [{log_time}] \"{request}\" {status} {size}"


def main():
    for line in sys.stdin:
        line = line.rstrip("\n")
        match_obj = log_pattern.match(line)
        if match_obj:
            print(convert_log_entry(match_obj))

main()
