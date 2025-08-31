package dev.mark.code.api.model;

import lombok.Getter;

import java.util.Objects;

@Getter
public class ThreatResult {
    private final ThreatType type;
    private final RiskLevel riskLevel;
    private final String className;
    private final String methodName;
    private final String description;
    private final String details;
    private final int lineNumber;

    @Getter
    public enum ThreatType {
        URL("URL Detection"),
        ENCRYPTION("Encryption/Decryption"),
        WEB_CONNECTION("Web Connection"),
        COMMAND_EXECUTION("Command Execution");

        private final String displayName;

        ThreatType(String displayName) {
            this.displayName = displayName;
        }
    }

    @Getter
    public enum RiskLevel {
        LOW("Low", "#4CAF50"),
        MEDIUM("Medium", "#FF9800"),
        HIGH("High", "#F44336"),
        CRITICAL("Critical", "#9C27B0");

        private final String displayName;
        private final String color;

        RiskLevel(String displayName, String color) {
            this.displayName = displayName;
            this.color = color;
        }
    }

    public ThreatResult(ThreatType type, RiskLevel riskLevel, String className, String methodName, String description, String details, int lineNumber) {
        this.type = type;
        this.riskLevel = riskLevel;
        this.className = className;
        this.methodName = methodName;
        this.description = description;
        this.details = details;
        this.lineNumber = lineNumber;
    }

    public ThreatResult(ThreatType type, RiskLevel riskLevel, String className, String methodName, String description, String details) {
        this(type, riskLevel, className, methodName, description, details, -1);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ThreatResult that = (ThreatResult) o;
        return lineNumber == that.lineNumber && type == that.type && Objects.equals(className, that.className) && Objects.equals(methodName, that.methodName) && Objects.equals(description, that.description);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, className, methodName, description, lineNumber);
    }

    @Override
    public String toString() {
        return String.format("[%s] %s.%s: %s", riskLevel.getDisplayName(), className, methodName, description);
    }
}