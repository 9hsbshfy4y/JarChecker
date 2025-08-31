package dev.mark.code.util;

import dev.mark.code.api.model.ThreatResult;
import dev.mark.code.constants.ThreatPatterns;

public final class RiskEvaluator {

    public static ThreatResult.RiskLevel evaluateUrlRisk(String url) {
        String lowerUrl = url.toLowerCase();

        if (StringUtils.containsAny(lowerUrl, ThreatPatterns.CRITICAL_URL_KEYWORDS)) {
            return ThreatResult.RiskLevel.CRITICAL;
        }

        if (StringUtils.containsAny(lowerUrl, ThreatPatterns.HIGH_RISK_URL_KEYWORDS) ||
                lowerUrl.matches(".*://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+.*")) {
            return ThreatResult.RiskLevel.HIGH;
        }

        if (StringUtils.containsAny(lowerUrl, ThreatPatterns.MEDIUM_RISK_URL_KEYWORDS)) {
            return ThreatResult.RiskLevel.MEDIUM;
        }

        return ThreatResult.RiskLevel.LOW;
    }

    public static ThreatResult.RiskLevel evaluateAlgorithmRisk(String algorithm) {
        return switch (algorithm.toUpperCase()) {
            case "AES", "RSA", "BLOWFISH", "TWOFISH" -> ThreatResult.RiskLevel.HIGH;
            default -> ThreatResult.RiskLevel.MEDIUM;
        };
    }

    public static ThreatResult.RiskLevel evaluateHashAlgorithmRisk(String algorithm) {
        return ThreatPatterns.WEAK_HASH_ALGORITHMS.contains(algorithm) ? ThreatResult.RiskLevel.MEDIUM : ThreatResult.RiskLevel.LOW;
    }

    public static ThreatResult.RiskLevel enhanceRiskWithContext(ThreatResult.RiskLevel currentRisk) {
        return switch (currentRisk) {
            case LOW -> ThreatResult.RiskLevel.MEDIUM;
            case MEDIUM -> ThreatResult.RiskLevel.HIGH;
            default -> currentRisk;
        };
    }
}