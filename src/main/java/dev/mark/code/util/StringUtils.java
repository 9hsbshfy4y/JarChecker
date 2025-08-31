package dev.mark.code.util;

import java.util.Set;

public final class StringUtils {
    public static String getSimpleClassName(String fullClassName) {
        if (fullClassName == null) return "unknown";
        int lastSlash = fullClassName.lastIndexOf('/');
        return lastSlash >= 0 ? fullClassName.substring(lastSlash + 1) : fullClassName;
    }

    public static String truncateString(String str, int maxLength) {
        if (str == null) return "";
        return str.length() > maxLength ? str.substring(0, maxLength - 3) + "..." : str;
    }

    public static boolean containsAny(String text, Set<String> keywords) {
        return keywords.stream().anyMatch(text::contains);
    }

    public static boolean isPrivateIP(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;

        try {
            int first = Integer.parseInt(parts[0]);
            int second = Integer.parseInt(parts[1]);

            return (first == 10) || (first == 172 && second >= 16 && second <= 31) || (first == 192 && second == 168) || (first == 127);
        } catch (NumberFormatException e) {
            return false;
        }
    }
}