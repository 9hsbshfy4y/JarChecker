package dev.mark.code.impl;

public record CheckConfig(boolean url, boolean encrypt, boolean webConnect, boolean command, boolean socket) {
    public boolean isEnabled(ThreatCheckerFactory.CheckerType type) {
        return switch (type) {
            case URL -> url;
            case ENCRYPTION -> encrypt;
            case WEB_CONNECTION -> webConnect;
            case COMMAND_EXECUTION -> command;
            case SOCKET_CONNECTION -> socket;
        };
    }
}