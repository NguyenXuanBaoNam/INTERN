import sys, re #sys để đọc input, re để tách, xử lý chuỗi
from datetime import datetime

#dùng để bắt chính xác từng trường trong log
pattern = re.compile(
#\S+: ăn(lưu) hết 1 chuỗi kí tự không có khoảng trắng
#\s+: nuốt 1 kí tự là khoảng trắng
     r'^(?P<remote_addr>\S+)\s+' 
            r'(?P<xff>\S+)\s+'
            r'\[(?P<time_iso8601>[^\]]+)\]\s+' #[^\]]+ bắt tất cả những kí tự không phải dấu ]
            r'(?P<http_host>\S+)\s+'
            r'"(?P<request>[^"]*)"\s+'
            r'(?P<status>\d{3})\s+'
            r'(?P<bytes_sent>\S+)\s+'
            r'"(?P<referer>[^"]*)"\s+'
            r'"(?P<ua>[^"]*)"\s+'
            r'(?P<gzip_ratio>\S+)\s+'
            r'(?P<req_len>\S+)\s+'
            r'(?P<req_time>\S+)\s*$',
    re.ASCII #re.ASCII làm cho \d, \s, \w chỉ match ASCII (nhanh/chuẩn hơn cho log tiếng Anh/ASCII).
)

def pick_ip(xff: str, remote_adrr: str) ->str:
    if xff and xff != '-' and xff.strip():
        return xff.split(',')[0].strip()
    else:
        return remote_adrr

def normalize_time(timeiso: str)-> str:
    try: #nếu chuẩn hóa được
        timeCLF = timeiso.replace('Z', '+00:00' )
        dt=datetime.fromisoformat(timeCLF)
        return dt.strftime("%d/%b/%Y:%H:%M:%S %z")
    except Exception: #nếu không chuẩn hóa được
        return timeiso

def convert_log(m)->str:
    ip = pick_ip(m['xff'], m['remote_addr'])
    time = normalize_time(m['time_iso8601'])
    request = m['request']
    status = m['status']
    size = m['bytes_sent']

def main():
    for line in sys.stdin:
        line = line.rstrip("\n") #rstrip: xóa bỏ kí tự xuống dòng ở cuối chuỗi nếu có
        m = pattern.match(line)
        if m:
            print(convert_log(m))

main()


