package dev.mark.code.util;

import java.util.regex.Pattern;

public final class PatternMatcher {
    public static final Pattern IP_PATTERN = Pattern.compile(
            "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"
    );

    public static final Pattern URL_PATTERN = Pattern.compile(
            "(?i)\\b(?:https?://|ftp://|www\\.|[a-zA-Z0-9][-a-zA-Z0-9]*\\.(?:com|org|net|edu|gov|mil|int|co|io|me|tv|tk|ml|ga|cf))[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]"
    );

    public static final Pattern BASE64_PATTERN = Pattern.compile(
            "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    );

    public static final Pattern SUSPICIOUS_DOMAIN_PATTERN = Pattern.compile(
            "(?i)\\b(?:bit\\.ly|tinyurl\\.com|t\\.co|goo\\.gl|ow\\.ly|short\\.link|discord\\.gg|pastebin\\.com)"
    );
}