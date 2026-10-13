import argparse
import csv
import re
import sys
from collections import Counter


FAILED_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<hour>\d{2}):\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)

def parse_log(path):
    attempts = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                match = FAILED_RE.search(line)
                if match:
                    attempts.append(match.groupdict())
    except FileNotFoundError:
        sys.exit(f"Hata: '{path}' dosyası bulunamadı")
    except PermissionError:
        sys.exit(f"Hata: '{path} okunamıyor. (izin yok).'")
    return attempts

def analyze(attempts):
    ips = Counter(a["ip"] for a in attempts)
    users = Counter(a["user"] for a in attempts)
    hours = Counter(a["hour"] for a in attempts)
    return ips, users, hours

def print_report(attempts, ips, users, hours, top):
    print(f"Toplam başarısız giriş denemesi: {len(attempts)}\n")

    print(f"En çok deneme yapan {top} IP:")
    for ip, count in ips.most_common(top):
        print(f" {ip:<18} {count}")

    print(f"\nEn çok denenen {top} kullanıcı adı:")
    for user, count in users.most_common(top):
        print(f" {user:<18} {count}")

    print(f"\nSaate göre dağılım:")
    for hour in sorted(hours):
        print(f" {hour}:00 {'#' * hours[hour]} ({hours[hour]})")

def save_csv(ips, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip","deneme_sayisi"])
        writer.writerows(ips.most_common())
    print(f"\nCSV raporu kaydedildi: {path}")

def main():
    parser = argparse.ArgumentParser(description="SSH başarısız giriş analizi")
    parser.add_argument("logfile", help="Analiz edilecek log dosyası")
    parser.add_argument("--top", type=int, default=10, help="Listelenecek kayıt sayısı")
    parser.add_argument("--csv", help="IP raporunu CSV olarak kaydet")
    args = parser.parse_args()



    attempts = parse_log(args.logfile)
    if not attempts:
        sys.exit("Başarısız giriş denemesi bulunamadı.")

    ips, users, hours = analyze(attempts)
    print_report(attempts, ips, users, hours, args.top)

    if args.csv:
        save_csv(ips,args.csv)

if __name__ == "__main__":
    main()

    











