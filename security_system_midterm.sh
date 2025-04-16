#!/bin/bash

# 실습 환경 설정
echo "리눅스 명령어 실습 환경을 설정합니다..."

# 실습용 디렉토리 구조 생성
mkdir -p ~/linuxlab/{data,logs,scripts,config,backup}

# 실습용 파일 생성
echo "Hello Linux!" > ~/linuxlab/data/hello.txt
echo "user1,김철수,개발팀" > ~/linuxlab/data/users.txt
echo "user2,이영희,보안팀" >> ~/linuxlab/data/users.txt
echo "user3,박지민,운영팀" >> ~/linuxlab/data/users.txt

# 로그 파일 샘플 데이터
cat > ~/linuxlab/logs/access.log << 'EOF'
192.168.1.100 - - [15/Apr/2025:10:12:34 +0900] "GET /index.html HTTP/1.1" 200 1234
192.168.1.101 - - [15/Apr/2025:10:14:22 +0900] "GET /about.html HTTP/1.1" 200 4567
10.0.0.55 - - [15/Apr/2025:10:15:01 +0900] "GET /admin.php HTTP/1.1" 403 301
EOF

# 스크립트 파일 샘플
cat > ~/linuxlab/scripts/hello.sh << 'EOF'
#!/bin/bash
echo "Hello, $(whoami)!"
echo "Today is $(date)"
EOF

# 권한 설정
chmod 755 ~/linuxlab/scripts/hello.sh

# 완료 메시지
echo "환경 설정이 완료되었습니다."
echo "실습용 디렉토리는 ~/linuxlab 입니다."
