#!/bin/bash
# DVWA 웹 서버 보호를 위한 iptables 설정 스크립트

# iptables 설치 확인 및 설치
echo "iptables 설치 확인 중..."
if ! dpkg -l | grep -q iptables; then
    echo "iptables 설치 중..."
    apt update
    apt install iptables -y
fi

# iptables-persistent 설치 확인 및 설치
if ! dpkg -l | grep -q iptables-persistent; then
    echo "iptables-persistent 설치 중..."
    # 자동으로 Yes 응답을 위한 사전 설정
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
    apt install iptables-persistent -y
fi

# 규칙 초기화
echo "초기화 중..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# 기본 정책 설정
echo "기본 정책 설정 중..."
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 로컬호스트 접근 허용
echo "로컬호스트 허용 중..."
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 기존 연결 허용
echo "기존 연결 및 관련 연결 허용 중..."
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# SSH 접근 제한
echo "SSH 접근 설정 중..."
iptables -A INPUT -p tcp -s 192.168.0.10 --dport 22 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# HTTP/HTTPS 허용
echo "웹 서버 접근 설정 중..."
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# 웹 요청 속도 제한
echo "DoS 방어 설정 중..."
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 20/minute --limit-burst 100 -j ACCEPT

# SQL 인젝션 방어
echo "SQL 인젝션 방어 중..."
iptables -A INPUT -p tcp --dport 80 -m string --string "UNION SELECT" --algo bm -j DROP
iptables -A INPUT -p tcp --dport 80 -m string --string "OR 1=1" --algo bm -j DROP

# XSS 방어
echo "XSS 방어 중..."
iptables -A INPUT -p tcp --dport 80 -m string --string "<script>" --algo bm -j DROP
iptables -A INPUT -p tcp --dport 80 -m string --string "alert(" --algo bm -j DROP

# 포트 스캔 방어
echo "포트 스캔 방어 중..."
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP

# SYN 플러드 방어
echo "SYN 플러드 방어 중..."
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# ICMP 제한
echo "ICMP 제한 중..."
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# 악의적인 IP 차단
echo "공격자 IP 차단 설정 중..."
iptables -A INPUT -s 192.168.0.10 -p tcp --dport 80 -m recent --name blacklist --set
iptables -A INPUT -s 192.168.0.10 -p tcp --dport 80 -m recent --name blacklist --update --seconds 3600 --hitcount 10 -j DROP

# 로깅
echo "로깅 설정 중..."
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4

# 규칙 저장
echo "규칙 저장 중..."
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
    netfilter-persistent reload
else
    echo "netfilter-persistent가 설치되지 않았습니다. 수동으로 규칙을 저장하세요."
    echo "Ubuntu: sudo apt install iptables-persistent"
fi

echo "방화벽 설정이 완료되었습니다."
iptables -L -v
