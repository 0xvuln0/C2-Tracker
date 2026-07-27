/*
 * Web shell detection rules.
 * Covers PHP, ASP/ASPX, JSP, and generic web shell patterns.
 */

rule PHPWebShellAdvanced {
    meta:
        description = "Detects PHP web shells with command execution capabilities"
        severity = "critical"
        category = "webshell"
    strings:
        $eval_user1 = "eval($_GET" ascii
        $eval_user2 = "eval($_POST" ascii
        $eval_user3 = "eval($_REQUEST" ascii
        $assert_user1 = "assert($_GET" ascii
        $assert_user2 = "assert($_POST" ascii
        $shell_exec1 = "shell_exec($_GET" ascii
        $shell_exec2 = "shell_exec($_POST" ascii
        $passthru1 = "passthru($_GET" ascii
        $passthru2 = "passthru($_POST" ascii
        $system1 = "system($_GET" ascii
        $system2 = "system($_POST" ascii
        $proc_open1 = "proc_open($_GET" ascii
        $proc_open2 = "proc_open($_POST" ascii
        $popen1 = "popen($_GET" ascii
        $popen2 = "popen($_POST" ascii
        $exec1 = "exec($_GET" ascii
        $exec2 = "exec($_POST" ascii
        $b64_eval = "eval(base64_decode" ascii
        $php_shell = "PD9waHA" ascii
    condition:
        2 of them
}

rule PHPFileUploader {
    meta:
        description = "Detects PHP file upload web shells"
        severity = "high"
        category = "webshell"
    strings:
        $upload1 = "move_uploaded_file" ascii
        $upload2 = "is_uploaded_file" ascii
        $dir1 = "scandir(" ascii
        $dir2 = "readdir(" ascii
        $file_put = "file_put_contents" ascii
        $fwrite = "fwrite(" ascii
        $user_input1 = "$_FILES[" ascii
        $user_input2 = "$_GET[" ascii
    condition:
        ($upload1 and $user_input1) or
        ($upload2 and $user_input1) or
        ($file_put and $user_input2 and 1 of ($dir*)) or
        ($fwrite and $user_input2 and 1 of ($dir*))
}

rule ASPXWebShell {
    meta:
        description = "Detects ASPX web shells"
        severity = "critical"
        category = "webshell"
    strings:
        $aspx1 = "<%eval(Request" ascii nocase
        $aspx2 = "<%eval request" ascii nocase
        $aspx3 = "<%@ Page Language" ascii nocase
        $aspx4 = "System.Diagnostics.Process.Start" ascii
        $aspx5 = "ProcessStartInfo" ascii
        $aspx6 = "cmd.exe /c" ascii
        $aspx7 = "Response.Write(" ascii
        $aspx8 = "Request(" ascii
    condition:
        ($aspx1 and $aspx6) or
        ($aspx2 and $aspx6) or
        ($aspx4 and $aspx5) or
        ($aspx3 and $aspx7 and $aspx8)
}

rule JSPWebShell {
    meta:
        description = "Detects JSP/Java web shells"
        severity = "high"
        category = "webshell"
    strings:
        $jsp1 = "Runtime.getRuntime().exec" ascii
        $jsp2 = "ProcessBuilder" ascii
        $jsp3 = "getParameter(" ascii
        $jsp4 = "request.getParameter" ascii
        $jsp5 = "getInputStream" ascii
        $jsp6 = "BufferedReader" ascii
        $jsp7 = "InputStreamReader" ascii
    condition:
        ($jsp1 and $jsp3) or
        ($jsp2 and $jsp3 and $jsp5) or
        ($jsp4 and $jsp5 and ($jsp6 or $jsp7))
}

rule GenericWebShellObfuscation {
    meta:
        description = "Detects obfuscated web shell patterns"
        severity = "high"
        category = "webshell"
    strings:
        $b64_decode = "base64_decode" ascii
        $eval1 = "eval(" ascii
        $eval2 = "assert(" ascii
        $gzinflate = "gzinflate" ascii
        $gzuncompress = "gzuncompress" ascii
        $str_rot13 = "str_rot13" ascii
        $chr1 = "chr(" ascii
        $char_map = "str_replace" ascii
    condition:
        ($b64_decode and ($eval1 or $eval2)) or
        ($gzinflate and ($eval1 or $eval2)) or
        ($gzuncompress and ($eval1 or $eval2)) or
        ($str_rot13 and ($eval1 or $eval2)) or
        (#chr1 > 10 and ($eval1 or $eval2)) or
        ($char_map and $b64_decode) or
        ($b64_decode and $gzinflate and ($eval1 or $eval2))
}
