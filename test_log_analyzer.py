import pytest

from log_analyzer import FAILED_RE, analyze, parse_log

SAMPLE_LOG = """\
Oct 13 03:12:45 server sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2
Oct 13 03:12:50 server sshd[1234]: Failed password for root from 203.0.113.5 port 52150 ssh2
Oct 13 04:30:11 server sshd[1301]: Failed password for invalid user test from 198.51.100.7 port 40022 ssh2
Oct 13 04:30:15 server sshd[1301]: Failed password for root from 198.51.100.7 port 40025 ssh2
Oct 13 04:30:19 server sshd[1301]: Failed password for root from 203.0.113.5 port 40030 ssh2
Oct 13 05:00:00 server sshd[1400]: Accepted password for emir from 192.168.1.10 port 50000 ssh2
Oct 13 05:01:00 server CRON[999]: pam_unix(cron:session): session opened for user root
"""

@pytest.fixture
def log_file(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(SAMPLE_LOG, encoding="utf-8")
    return str(path)


# --- Regex Testleri ---

@pytest.mark.parametrize(
    "line, user, ip, hour",
    [
        (
            "Oct 13 03:12:45 server sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2",
            "admin", "203.0.113.5", "03",
        ),
        (
            "Oct 13 03:12:50 server sshd[1234]: Failed password for root from 203.0.113.5 port 52150 ssh2",
            "root", "203.0.113.5", "03",
        ),
        (
            "Oct 13 23:59:59 server sshd[1]: Failed password for invalid user test from 198.51.100.7 port 22 ssh2",
            "test", "198.51.100.7", "23",
        ),
    ],
    ids=["invalid-user", "valid-user", "gece-yarisi"],
)

def test_regex_matches_failed_login(line, user, ip, hour):
    match = FAILED_RE.search(line)
    assert match is not None
    assert match["user"] == user
    assert match["ip"] == ip
    assert match["hour"] == hour

@pytest.mark.parametrize(
    "line",
    [
        "Oct 13 05:00:00 server sshd[1400]: Accepted password for emir from 192.168.1.10 port 50000 ssh2",
        "Oct 13 05:01:00 server CRON[999]: pam_unix(cron:session): session opened for user root",
        "",
    ],
    ids=["basarili-giris", "cron-satiri", "bos-satir"],
)
def test_regex_ignores_other_lines(line):
    assert FAILED_RE.search(line) is None


# --- parse_log testleri ---
 
def test_parse_log_counts_only_failed_attempts(log_file):
    attempts = parse_log(log_file)
    assert len(attempts) == 5
 
 
def test_parse_log_returns_expected_fields(log_file):
    first = parse_log(log_file)[0]
    assert first["user"] == "admin"
    assert first["ip"] == "203.0.113.5"
 
 
def test_parse_log_empty_file(tmp_path):
    path = tmp_path / "empty.log"
    path.write_text("", encoding="utf-8")
    assert parse_log(str(path)) == []
 
 
def test_parse_log_missing_file_exits(tmp_path):
    with pytest.raises(SystemExit):
        parse_log(str(tmp_path / "yok.log"))
 
 
# --- analyze testleri ---
 
def test_analyze_counts_ips(log_file):
    ips, _, _ = analyze(parse_log(log_file))
    assert ips["203.0.113.5"] == 3
    assert ips["198.51.100.7"] == 2
 
 
def test_analyze_counts_users(log_file):
    _, users, _ = analyze(parse_log(log_file))
    assert users["root"] == 3
    assert users["admin"] == 1
    assert users["test"] == 1
 
 
def test_analyze_counts_hours(log_file):
    _, _, hours = analyze(parse_log(log_file))
    assert hours["03"] == 2
    assert hours["04"] == 3
 
 
def test_analyze_most_common_order(log_file):
    ips, _, _ = analyze(parse_log(log_file))
    assert ips.most_common(1)[0] == ("203.0.113.5", 3)
 