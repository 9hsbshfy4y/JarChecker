package dev.mark.code.impl;

import dev.mark.code.impl.checks.*;
import lombok.Getter;

import java.util.Arrays;
import java.util.Map;

public class ThreatCheckerFactory {
    public enum CheckerType {
        URL("URL Detection"),
        ENCRYPTION("Encryption/Crypto"),
        WEB_CONNECTION("Web Connections"),
        COMMAND_EXECUTION("Command Execution"),
        SOCKET_CONNECTION("Socket Connections");

        @Getter
        private final String displayName;

        CheckerType(String displayName) {
            this.displayName = displayName;
        }
    }

    private static final Map<CheckerType, AbstractThreatChecker> CHECKER_INSTANCES = Map.of(
            CheckerType.URL, new UrlCheck(),
            CheckerType.ENCRYPTION, new FileEncryptCheck(),
            CheckerType.WEB_CONNECTION, new WebConnectCheck(),
            CheckerType.COMMAND_EXECUTION, new CommandExecCheck()
    );

    public static AbstractThreatChecker getChecker(CheckerType type) {
        return CHECKER_INSTANCES.get(type);
    }

    public static String[] getAllDisplayNames() {
        return Arrays.stream(CheckerType.values()).map(CheckerType::getDisplayName).toArray(String[]::new);
    }
}