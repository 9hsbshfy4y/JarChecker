package dev.mark.code.impl.checks;

import dev.mark.code.api.model.ThreatResult;
import dev.mark.code.constants.ThreatPatterns;
import dev.mark.code.impl.AbstractThreatChecker;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;

public class WebConnectCheck extends AbstractThreatChecker {

    public WebConnectCheck() {
        super(ThreatResult.ThreatType.WEB_CONNECTION);
    }

    @Override
    protected void analyzeMethod(ClassNode classNode, MethodNode methodNode, List<ThreatResult> results) {
        analyzeInstructions(classNode, methodNode, results);
    }

    @Override
    protected void analyzeStringConstant(String value, String className, String methodName, List<ThreatResult> results) {
        analyzeHttpMethod(value, className, methodName, results);
        analyzeHttpHeaders(value, className, methodName, results);
        analyzeBrowserAgent(value, className, methodName, results);
        analyzeContentType(value, className, methodName, results);
    }

    private void analyzeHttpMethod(String value, String className, String methodName, List<ThreatResult> results) {
        if (ThreatPatterns.SUSPICIOUS_HTTP_METHODS.contains(value.toUpperCase())) {
            results.add(createThreatResult(
                    ThreatResult.RiskLevel.MEDIUM, className, methodName,
                    "HTTP method: " + value.toUpperCase(),
                    "Potentially dangerous HTTP method for data modification"
            ));
        }
    }

    private void analyzeHttpHeaders(String value, String className, String methodName, List<ThreatResult> results) {
        String lowerValue = value.toLowerCase();

        for (String header : ThreatPatterns.SUSPICIOUS_HEADERS) {
            if (lowerValue.equals(header) || lowerValue.contains(header + ":")) {
                ThreatResult.RiskLevel risk = ThreatPatterns.HIGH_RISK_HEADERS.contains(header) ? ThreatResult.RiskLevel.HIGH : ThreatResult.RiskLevel.MEDIUM;

                results.add(createThreatResult(
                        risk, className, methodName,
                        "Suspicious HTTP header: " + header,
                        "Header value: " + truncateString(value, 60)
                ));
                return;
            }
        }
    }

    private void analyzeBrowserAgent(String value, String className, String methodName, List<ThreatResult> results) {
        String lowerValue = value.toLowerCase();
        if (ThreatPatterns.BROWSER_AGENTS.stream().anyMatch(lowerValue::contains)) {
            results.add(createThreatResult(
                    ThreatResult.RiskLevel.MEDIUM, className, methodName,
                    "Browser User-Agent spoofing",
                    "User-Agent: " + truncateString(value, 60)
            ));
        }
    }

    private void analyzeContentType(String value, String className, String methodName, List<ThreatResult> results) {
        String lowerValue = value.toLowerCase();

        if (lowerValue.startsWith("application/") || lowerValue.startsWith("text/") || lowerValue.startsWith("multipart/")) {
            results.add(createThreatResult(
                    ThreatResult.RiskLevel.LOW, className, methodName,
                    "Content-Type header",
                    "Content-Type: " + value
            ));
        }
    }

    @Override
    protected void analyzeMethodCall(MethodInsnNode methodInsnNode, String className, String methodName, String currentUrl, List<ThreatResult> results) {
        if (isWebConnectionMethod(methodInsnNode)) {
            handleWebConnectionMethod(methodInsnNode, className, methodName, currentUrl, results);
        } else if (isThirdPartyHttpClient(methodInsnNode.owner)) {
            handleThirdPartyHttpClient(methodInsnNode, className, methodName, results);
        } else if (isSslBypassAttempt(methodInsnNode)) {
            handleSslBypassAttempt(className, methodName, results);
        }
    }

    private boolean isWebConnectionMethod(MethodInsnNode methodInsnNode) {
        return ThreatPatterns.WEB_CONNECTION_CLASSES.contains(methodInsnNode.owner);
    }

    private void handleWebConnectionMethod(MethodInsnNode methodInsnNode, String className, String methodName, String currentUrl, List<ThreatResult> results) {
        ThreatResult.RiskLevel risk = ThreatPatterns.DANGEROUS_HTTP_METHODS.contains(methodInsnNode.name) ? ThreatResult.RiskLevel.HIGH : ThreatResult.RiskLevel.MEDIUM;

        String description = String.format("Web connection method: %s.%s", getSimpleClassName(methodInsnNode.owner), methodInsnNode.name);

        StringBuilder details = buildMethodDetails(methodInsnNode, currentUrl);

        if (currentUrl != null) {
            risk = ThreatResult.RiskLevel.HIGH;
        }

        results.add(createThreatResult(risk, className, methodName, description, details.toString()));
    }

    private void handleThirdPartyHttpClient(MethodInsnNode methodInsnNode, String className, String methodName, List<ThreatResult> results) {
        results.add(createThreatResult(
                ThreatResult.RiskLevel.MEDIUM, className, methodName,
                "Third-party HTTP client usage",
                "Library: " + getSimpleClassName(methodInsnNode.owner)
        ));
    }

    private void handleSslBypassAttempt(String className, String methodName, List<ThreatResult> results) {
        results.add(createThreatResult(
                ThreatResult.RiskLevel.HIGH, className, methodName,
                "SSL/TLS security bypass attempt",
                "May disable certificate validation"
        ));
    }

    private boolean isThirdPartyHttpClient(String owner) {
        return owner.contains("apache/http") || owner.contains("okhttp") || owner.contains("retrofit");
    }

    private boolean isSslBypassAttempt(MethodInsnNode methodInsnNode) {
        return methodInsnNode.owner.contains("TrustManager") || methodInsnNode.owner.contains("HostnameVerifier") || "setHostnameVerifier".equals(methodInsnNode.name) || "setSSLSocketFactory".equals(methodInsnNode.name);
    }

    private StringBuilder buildMethodDetails(MethodInsnNode methodInsnNode, String currentUrl) {
        StringBuilder details = new StringBuilder().append("Method: ").append(methodInsnNode.owner).append(".").append(methodInsnNode.name).append(methodInsnNode.desc);

        if (currentUrl != null) {
            details.append("\nURL: ").append(truncateString(currentUrl, 60));
        }

        return details;
    }
}
