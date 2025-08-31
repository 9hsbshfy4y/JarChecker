package dev.mark.code.impl.checks;

import dev.mark.code.api.model.ThreatResult;
import dev.mark.code.constants.ThreatPatterns;
import dev.mark.code.impl.AbstractThreatChecker;
import dev.mark.code.util.PatternMatcher;
import dev.mark.code.util.RiskEvaluator;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;

public class FileEncryptCheck extends AbstractThreatChecker {

    public FileEncryptCheck() {
        super(ThreatResult.ThreatType.ENCRYPTION);
    }

    @Override
    protected void analyzeMethod(ClassNode classNode, MethodNode methodNode, List<ThreatResult> results) {
        analyzeInstructions(classNode, methodNode, results);
    }

    @Override
    protected void analyzeStringConstant(String value, String className, String methodName, List<ThreatResult> results) {
        analyzeEncryptionAlgorithm(value, className, methodName, results);
        analyzeHashAlgorithm(value, className, methodName, results);
        analyzeCryptoMode(value, className, methodName, results);
        analyzeBase64Data(value, className, methodName, results);
    }

    private void analyzeEncryptionAlgorithm(String value, String className, String methodName, List<ThreatResult> results) {
        String upperValue = value.toUpperCase();

        for (String algorithm : ThreatPatterns.RANSOMWARE_ALGORITHMS) {
            if (upperValue.contains(algorithm)) {
                ThreatResult.RiskLevel risk = RiskEvaluator.evaluateAlgorithmRisk(algorithm);
                results.add(createThreatResult(
                        risk, className, methodName,
                        "Encryption algorithm: " + algorithm,
                        "Algorithm string: " + value
                ));
                return;
            }
        }
    }

    private void analyzeHashAlgorithm(String value, String className, String methodName, List<ThreatResult> results) {
        String upperValue = value.toUpperCase();

        for (String hashAlg : ThreatPatterns.HASH_ALGORITHMS) {
            if (upperValue.contains(hashAlg)) {
                ThreatResult.RiskLevel risk = RiskEvaluator.evaluateHashAlgorithmRisk(hashAlg);
                results.add(createThreatResult(
                        risk, className, methodName,
                        "Hash algorithm: " + hashAlg,
                        "Algorithm string: " + value
                ));
                return;
            }
        }
    }

    private void analyzeCryptoMode(String value, String className, String methodName, List<ThreatResult> results) {
        String upperValue = value.toUpperCase();
        for (String mode : ThreatPatterns.CRYPTO_MODES) {
            if (upperValue.contains(mode)) {
                ThreatResult.RiskLevel risk = "ECB".equals(mode) ? ThreatResult.RiskLevel.MEDIUM : ThreatResult.RiskLevel.LOW;

                results.add(createThreatResult(
                        risk, className, methodName,
                        "Encryption mode detected",
                        "Mode string: " + value
                ));
                return;
            }
        }
    }

    private void analyzeBase64Data(String value, String className, String methodName, List<ThreatResult> results) {
        if (value.length() > 10 && PatternMatcher.BASE64_PATTERN.matcher(value).matches()) {
            results.add(createThreatResult(
                    ThreatResult.RiskLevel.LOW, className, methodName,
                    "Potential Base64 encoded data",
                    "Data: " + truncateString(value, 50)
            ));
        }
    }

    @Override
    protected void analyzeMethodCall(MethodInsnNode methodInsnNode, String className, String methodName, String currentAlgorithm, List<ThreatResult> results) {
        if (ThreatPatterns.CRYPTO_CLASSES.contains(methodInsnNode.owner)) {
            handleCryptoMethod(methodInsnNode, className, methodName, currentAlgorithm, results);
        } else if (ThreatPatterns.BASE64_CLASSES.contains(methodInsnNode.owner)) {
            handleBase64Method(methodInsnNode, className, methodName, results);
        } else if ("java/security/SecureRandom".equals(methodInsnNode.owner)) {
            handleSecureRandomMethod(className, methodName, results);
        }
    }

    private void handleCryptoMethod(MethodInsnNode methodInsnNode, String className, String methodName, String currentAlgorithm, List<ThreatResult> results) {
        ThreatResult.RiskLevel risk = determineCryptoMethodRisk(methodInsnNode);

        String description = String.format("Cryptographic method: %s.%s", getSimpleClassName(methodInsnNode.owner), methodInsnNode.name);

        StringBuilder details = buildCryptoMethodDetails(methodInsnNode, currentAlgorithm);

        if (currentAlgorithm != null) {
            risk = RiskEvaluator.enhanceRiskWithContext(risk);
        }

        results.add(createThreatResult(risk, className, methodName, description, details.toString()));
    }

    private void handleBase64Method(MethodInsnNode methodInsnNode, String className, String methodName, List<ThreatResult> results) {
        results.add(createThreatResult(
                ThreatResult.RiskLevel.LOW, className, methodName,
                "Base64 encoding/decoding",
                "Method: " + methodInsnNode.name
        ));
    }

    private void handleSecureRandomMethod(String className, String methodName, List<ThreatResult> results) {
        results.add(createThreatResult(
                ThreatResult.RiskLevel.LOW, className, methodName,
                "Secure random number generation",
                "May be used for key generation or nonce creation"
        ));
    }

    private ThreatResult.RiskLevel determineCryptoMethodRisk(MethodInsnNode methodInsnNode) {
        return switch (methodInsnNode.name) {
            case "doFinal", "update" -> ThreatResult.RiskLevel.HIGH;
            case "getInstance" -> ThreatResult.RiskLevel.LOW;
            default -> ThreatResult.RiskLevel.MEDIUM;
        };
    }

    private StringBuilder buildCryptoMethodDetails(MethodInsnNode methodInsnNode, String currentAlgorithm) {
        StringBuilder details = new StringBuilder()
                .append("Method: ").append(methodInsnNode.owner)
                .append(".").append(methodInsnNode.name)
                .append(methodInsnNode.desc);

        if (currentAlgorithm != null) {
            details.append("\nAlgorithm: ").append(currentAlgorithm);
        }

        return details;
    }
}