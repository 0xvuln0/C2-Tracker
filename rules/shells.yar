/*
 * Reverse shell detection rules.
 * Covers bash, python, perl, ruby, php, java, and netcat reverse shells.
 */

rule BashReverseShellAdvanced {
    meta:
        description = "Detects bash reverse shell patterns with variations"
        severity = "critical"
        category = "reverse_shell"
    strings:
        $bash1 = "bash -i >& /dev/tcp/" ascii
        $bash2 = "0<&196;exec 196<>/dev/tcp/" ascii
        $bash3 = "bash -i 2>&1 1>/dev/tcp/" ascii
        $fifo1 = "mkfifo /tmp/" ascii
        $fifo2 = "nc -e /bin/" ascii
        $fifo3 = "rm /tmp/" ascii
    condition:
        any of ($bash*) or
        (#fifo1 > 0 and #fifo2 > 0 and #fifo3 > 0)
}

rule PythonReverseShellAdvanced {
    meta:
        description = "Detects Python reverse shell with import obfuscation"
        severity = "critical"
        category = "reverse_shell"
    strings:
        $import1 = "__import__('socket')" ascii
        $import2 = "__import__(\"socket\")" ascii
        $import3 = "import socket" ascii
        $connect = "connect((" ascii
        $sock_stream = "SOCK_STREAM" ascii
        $dup2 = "os.dup2" ascii
        $subprocess1 = "subprocess.Popen" ascii
        $subprocess2 = "subprocess.call" ascii
        $shell = "/bin/sh" ascii
        $bash = "/bin/bash" ascii
        $eval = "eval(" ascii
        $exec_func = "exec(" ascii
    condition:
        ($import1 and $connect and $sock_stream) or
        ($import2 and $connect and $sock_stream) or
        ($import3 and $connect and $sock_stream and $dup2) or
        ($subprocess1 and $dup2 and ($shell or $bash)) or
        ($subprocess2 and $dup2 and ($shell or $bash)) or
        ($eval and $import3 and $connect) or
        ($exec_func and $import3 and $connect)
}

rule PerlReverseShellAdvanced {
    meta:
        description = "Detects Perl reverse shell patterns"
        severity = "critical"
        category = "reverse_shell"
    strings:
        $perl1 = "use Socket" ascii
        $perl2 = "PF_INET" ascii
        $perl3 = "SOCK_STREAM" ascii
        $perl4 = "sockaddr_in" ascii
        $connect = "connect(" ascii
        $exec1 = "exec {'/bin/sh'}" ascii
        $exec2 = "exec('/bin/sh')" ascii
        $dup = "open(STDIN" ascii
        $dup2 = "open(STDOUT" ascii
    condition:
        ($perl1 and $perl2 and $perl3 and $perl4 and $connect) or
        ($exec1 and $dup and $dup2) or
        ($exec2 and $dup and $dup2)
}

rule RubyReverseShell {
    meta:
        description = "Detects Ruby reverse shell patterns"
        severity = "high"
        category = "reverse_shell"
    strings:
        $ruby1 = "TCPSocket.new" ascii
        $ruby2 = "TCPSocket.open" ascii
        $ruby3 = "exec(" ascii
        $ruby4 = "exec '" ascii
        $ruby5 = "IO.popen" ascii
        $ruby6 = "`/bin/sh`" ascii
        $ruby7 = "require 'socket'" ascii
    condition:
        ($ruby7 and $ruby1 and $ruby3) or
        ($ruby7 and $ruby2 and $ruby3) or
        ($ruby5 and $ruby6) or
        ($ruby7 and $ruby4 and $ruby6)
}

rule NetcatReverseShell {
    meta:
        description = "Detects netcat-based reverse shells"
        severity = "high"
        category = "reverse_shell"
    strings:
        $nc1 = "nc -e /bin/sh" ascii
        $nc2 = "nc -e /bin/bash" ascii
        $nc3 = "ncat -e /bin/sh" ascii
        $nc4 = "ncat -e /bin/bash" ascii
        $nc5 = "nc -l -p" ascii
        $nc6 = "nc -lvnp" ascii
        $socat1 = "socat TCP:" ascii
        $socat2 = "socat tcp:" ascii
        $mkfifo1 = "mkfifo" ascii
        $mkfifo2 = "nc " ascii
    condition:
        any of ($nc*, $socat*) or
        ($mkfifo1 and $mkfifo2)
}

rule PHPReverseShell {
    meta:
        description = "Detects PHP reverse shell patterns"
        severity = "critical"
        category = "reverse_shell"
    strings:
        $php1 = "fsockopen(" ascii
        $php2 = "proc_open(" ascii
        $php3 = "shell_exec(" ascii
        $php4 = "system(" ascii
        $php5 = "exec(" ascii
        $php6 = "passthru(" ascii
        $connect = "connect(" ascii
        $shell = "/bin/sh" ascii
        $bash = "/bin/bash" ascii
    condition:
        ($php1 and $connect and ($shell or $bash)) or
        ($php2 and $connect and ($shell or $bash)) or
        ($php3 and ($shell or $bash)) or
        ($php4 and ($shell or $bash)) or
        ($php5 and ($shell or $bash)) or
        ($php6 and ($shell or $bash))
}

rule PowerShellReverseShell {
    meta:
        description = "Detects PowerShell reverse shell patterns"
        severity = "critical"
        category = "reverse_shell"
    strings:
        $ps1 = "New-Object Net.Sockets.TCPClient" ascii nocase
        $ps2 = "New-Object Net.Sockets.UDPClient" ascii nocase
        $ps3 = "System.Net.Sockets.TcpClient" ascii
        $ps4 = "System.Net.Sockets.UdpClient" ascii
        $ps5 = "NetworkStream" ascii
        $ps6 = "StreamReader" ascii
        $ps7 = "StreamWriter" ascii
        $ps8 = "IEX(" ascii nocase
        $ps9 = "Invoke-Expression" ascii nocase
        $ps10 = "powershell -enc" ascii nocase
        $ps11 = "powershell -w hidden" ascii nocase
        $ps12 = "DownloadString" ascii
        $ps13 = "Net.WebClient" ascii
    condition:
        ($ps1 and $ps5 and $ps6 and $ps7) or
        ($ps2 and $ps5 and $ps6 and $ps7) or
        ($ps3 and $ps5 and $ps6 and $ps7) or
        ($ps4 and $ps5 and $ps6 and $ps7) or
        ($ps10 and $ps12) or
        ($ps10 and $ps13) or
        ($ps11 and ($ps8 or $ps9))
}
