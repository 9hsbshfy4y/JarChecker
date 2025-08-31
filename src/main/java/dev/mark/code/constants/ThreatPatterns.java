package dev.mark.code.constants;

import java.util.Set;

public final class ThreatPatterns {

    // Web Connection patterns
    public static final Set<String> WEB_CONNECTION_CLASSES = Set.of(
            "java/net/URLConnection", "java/net/HttpURLConnection", "javax/net/ssl/HttpsURLConnection",
            "java/net/URL", "org/apache/http/client/HttpClient", "org/apache/http/impl/client/HttpClients",
            "okhttp3/OkHttpClient", "java/net/http/HttpClient", "java/net/http/HttpRequest",
            "java/net/http/HttpResponse"
    );

    public static final Set<String> DANGEROUS_HTTP_METHODS = Set.of(
            "connect", "openConnection", "getInputStream", "getOutputStream",
            "setRequestMethod", "setRequestProperty", "addRequestProperty", "send", "sendAsync", "execute"
    );

    public static final Set<String> SUSPICIOUS_HTTP_METHODS = Set.of(
            "POST", "PUT", "PATCH", "DELETE"
    );

    public static final Set<String> SUSPICIOUS_HEADERS = Set.of(
            "user-agent", "authorization", "x-forwarded-for", "x-real-ip",
            "cookie", "set-cookie", "x-requested-with"
    );

    public static final Set<String> HIGH_RISK_HEADERS = Set.of(
            "authorization", "cookie", "set-cookie"
    );

    public static final Set<String> BROWSER_AGENTS = Set.of(
            "mozilla", "chrome", "firefox", "safari"
    );

    // Crypto patterns
    public static final Set<String> CRYPTO_CLASSES = Set.of(
            "javax/crypto/Cipher", "javax/crypto/KeyGenerator", "javax/crypto/SecretKey",
            "javax/crypto/spec/SecretKeySpec", "javax/crypto/spec/IvParameterSpec",
            "java/security/MessageDigest", "java/security/SecureRandom", "javax/crypto/Mac"
    );

    public static final Set<String> RANSOMWARE_ALGORITHMS = Set.of(
            "AES", "DES", "3DES", "RSA", "Blowfish", "Twofish"
    );

    public static final Set<String> HASH_ALGORITHMS = Set.of(
            "MD5", "SHA-1", "SHA-256", "SHA-512"
    );

    public static final Set<String> WEAK_HASH_ALGORITHMS = Set.of(
            "MD5", "SHA-1"
    );

    public static final Set<String> CRYPTO_MODES = Set.of(
            "ECB", "CBC", "CTR", "GCM"
    );

    public static final Set<String> BASE64_CLASSES = Set.of(
            "java/util/Base64$Encoder", "java/util/Base64$Decoder", "java/util/Base64"
    );

    // Command execution patterns
    public static final Set<String> COMMAND_EXECUTION_CLASSES = Set.of(
            "java/lang/Runtime", "java/lang/ProcessBuilder", "java/lang/Process"
    );

    public static final Set<String> SHELL_COMMANDS = Set.of(
            "cmd", "cmd.exe", "powershell", "powershell.exe", "sh", "bash",
            "/bin/sh", "/bin/bash", "wscript", "cscript"
    );

    public static final Set<String> DANGEROUS_COMMANDS = Set.of(
            "format", "del", "rm", "rmdir", "rd", "taskkill", "net user",
            "reg add", "reg delete", "schtasks", "at ", "wmic", "vssadmin",
            "bcdedit", "cipher", "fsutil", "netsh", "sc create", "sc delete"
    );

    public static final Set<String> EXECUTION_FLAGS = Set.of(
            "-c ", "/c ", "-command", "-exec"
    );

    public static final Set<String> SYSTEM_INFO_METHODS = Set.of(
            "getProperty", "getenv"
    );

    // URL patterns
    public static final Set<String> CRITICAL_URL_KEYWORDS = Set.of(
            "download", "payload", "exploit", "shell"
    );

    public static final Set<String> HIGH_RISK_URL_KEYWORDS = Set.of(
            ".exe", ".bat", ".ps1", "admin"
    );

    public static final Set<String> MEDIUM_RISK_URL_KEYWORDS = Set.of(
            "api", "upload", "config"
    );
}