package dev.mark.code.impl.checks;

import dev.mark.code.api.model.ThreatResult;
import dev.mark.code.impl.AbstractThreatChecker;
import dev.mark.code.util.PatternMatcher;
import dev.mark.code.util.RiskEvaluator;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;

public class UrlCheck extends AbstractThreatChecker {

    public UrlCheck() {
        super(ThreatResult.ThreatType.URL);
    }

    @Override
    protected void analyzeMethod(ClassNode classNode, MethodNode methodNode, List<ThreatResult> results) {
        analyzeInstructions(classNode, methodNode, results);
    }

    @Override
    protected void analyzeStringConstant(String value, String className, String methodName, List<ThreatResult> results) {
        analyzeUrl(value, className, methodName, results);
        analyzeSuspiciousDomain(value, className, methodName, results);
        analyzeIpAddress(value, className, methodName, results);
        analyzeBase64Data(value, className, methodName, results);
    }

    private void analyzeUrl(String value, String className, String methodName, List<ThreatResult> results) {
        if (PatternMatcher.URL_PATTERN.matcher(value).find()) {
            ThreatResult.RiskLevel risk = RiskEvaluator.evaluateUrlRisk(value);
            results.add(createThreatResult(
                    risk, className, methodName,
                    "URL found: " + truncateString(value, 50),
                    "Full URL: " + value
            ));
        }
    }

    private void analyzeSuspiciousDomain(String value, String className, String methodName, List<ThreatResult> results) {
        if (PatternMatcher.SUSPICIOUS_DOMAIN_PATTERN.matcher(value).find()) {
            results.add(createThreatResult(
                    ThreatResult.RiskLevel.HIGH, className, methodName,
                    "Suspicious domain: " + truncateString(value, 50),
                    "Potential URL shortener or suspicious service: " + value
            ));
        }
    }

    private void analyzeIpAddress(String value, String className, String methodName, List<ThreatResult> results) {
        if (PatternMatcher.IP_PATTERN.matcher(value).find()) {
            ThreatResult.RiskLevel risk = isPrivateIP(value) ? ThreatResult.RiskLevel.LOW : ThreatResult.RiskLevel.MEDIUM;

            results.add(createThreatResult(
                    risk, className, methodName,
                    "IP address found: " + value,
                    isPrivateIP(value) ? "Private IP address" : "Public IP address - potential C2"
            ));
        }
    }

    private void analyzeBase64Data(String value, String className, String methodName, List<ThreatResult> results) {
        if (value.length() > 20 && PatternMatcher.BASE64_PATTERN.matcher(value).matches()) {
            results.add(createThreatResult(
                    ThreatResult.RiskLevel.MEDIUM, className, methodName,
                    "Potential Base64 encoded data",
                    "Base64 string: " + truncateString(value, 50)
            ));
        }
    }
}