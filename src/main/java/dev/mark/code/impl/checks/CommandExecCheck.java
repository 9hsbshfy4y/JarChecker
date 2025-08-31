package dev.mark.code.impl.checks;

import dev.mark.code.api.model.ThreatResult;
import dev.mark.code.constants.ThreatPatterns;
import dev.mark.code.impl.AbstractThreatChecker;
import dev.mark.code.impl.InstructionContext;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.List;

public class CommandExecCheck extends AbstractThreatChecker {

    public CommandExecCheck() {
        super(ThreatResult.ThreatType.COMMAND_EXECUTION);
    }

    @Override
    protected void analyzeMethod(ClassNode classNode, MethodNode methodNode, List<ThreatResult> results) {
        InstructionContext context = new InstructionContext();
        analyzeInstructionsWithContext(classNode, methodNode, results, context);
    }

    private void analyzeInstructionsWithContext(ClassNode classNode, MethodNode methodNode, List<ThreatResult> results, InstructionContext context) {
        if (methodNode.instructions == null) return;

        AbstractInsnNode[] instructions = methodNode.instructions.toArray();

        for (AbstractInsnNode instruction : instructions) {
            processCommandInstruction(instruction, classNode, methodNode, context, results);
        }
    }

    private void processCommandInstruction(AbstractInsnNode instruction, ClassNode classNode, MethodNode methodNode, InstructionContext context, List<ThreatResult> results) {
        switch (instruction) {
            case LdcInsnNode ldcNode when ldcNode.cst instanceof String stringValue -> context.lastString = analyzeCommandString(stringValue, classNode.name, methodNode.name, results);
            case MethodInsnNode methodInsnNode -> analyzeMethodCall(methodInsnNode, classNode.name, methodNode.name, context.lastString, results);
            case TypeInsnNode typeInsnNode when isStringArrayCreation(typeInsnNode) -> handleStringArrayCreation(typeInsnNode, classNode.name, methodNode.name, results);
            default -> {}
        }
    }

    private boolean isStringArrayCreation(TypeInsnNode typeInsnNode) {
        return typeInsnNode.getOpcode() == Opcodes.ANEWARRAY && "java/lang/String".equals(typeInsnNode.desc);
    }

    private void handleStringArrayCreation(TypeInsnNode typeInsnNode, String className, String methodName, List<ThreatResult> results) {
        results.add(createThreatResult(
                ThreatResult.RiskLevel.MEDIUM, className, methodName,
                "String array creation (potential command arguments)",
                "Array type: " + typeInsnNode.desc
        ));
    }

    private String analyzeCommandString(String value, String className, String methodName, List<ThreatResult> results) {
        String lowerValue = value.toLowerCase();

        if (analyzeShellCommands(value, lowerValue, className, methodName, results)) return value;
        if (analyzeDangerousCommands(value, lowerValue, className, methodName, results)) return value;
        if (analyzeExecutionFlags(value, lowerValue, className, methodName, results)) return value;

        return null;
    }

    private boolean analyzeShellCommands(String value, String lowerValue, String className, String methodName, List<ThreatResult> results) {
        for (String shellCommand : ThreatPatterns.SHELL_COMMANDS) {
            if (lowerValue.contains(shellCommand)) {
                results.add(createThreatResult(
                        ThreatResult.RiskLevel.HIGH, className, methodName,
                        "Shell command found: " + shellCommand,
                        "Command string: " + truncateString(value, 100)
                ));
                return true;
            }
        }
        return false;
    }

    private boolean analyzeDangerousCommands(String value, String lowerValue, String className, String methodName, List<ThreatResult> results) {
        for (String dangerousCommand : ThreatPatterns.DANGEROUS_COMMANDS) {
            if (lowerValue.contains(dangerousCommand)) {
                results.add(createThreatResult(
                        ThreatResult.RiskLevel.CRITICAL, className, methodName,
                        "Dangerous command: " + dangerousCommand,
                        "Full command: " + truncateString(value, 100)
                ));
                return true;
            }
        }
        return false;
    }

    private boolean analyzeExecutionFlags(String value, String lowerValue, String className, String methodName, List<ThreatResult> results) {
        for (String flag : ThreatPatterns.EXECUTION_FLAGS) {
            if (lowerValue.contains(flag)) {
                results.add(createThreatResult(
                        ThreatResult.RiskLevel.HIGH, className, methodName,
                        "Command execution flag detected",
                        "Command: " + truncateString(value, 100)
                ));
                return true;
            }
        }
        return false;
    }

    @Override
    protected void analyzeMethodCall(MethodInsnNode methodInsnNode, String className, String methodName, String currentCommand, List<ThreatResult> results) {
        if (ThreatPatterns.COMMAND_EXECUTION_CLASSES.contains(methodInsnNode.owner)) {
            handleCommandExecutionMethod(methodInsnNode, className, methodName, currentCommand, results);
        } else if (isSystemInfoMethod(methodInsnNode)) {
            handleSystemInfoMethod(methodInsnNode, className, methodName, results);
        }
    }

    private boolean isSystemInfoMethod(MethodInsnNode methodInsnNode) {
        return "java/lang/System".equals(methodInsnNode.owner) && ThreatPatterns.SYSTEM_INFO_METHODS.contains(methodInsnNode.name);
    }

    private void handleCommandExecutionMethod(MethodInsnNode methodInsnNode, String className, String methodName, String currentCommand, List<ThreatResult> results) {
        ThreatResult.RiskLevel risk = ThreatPatterns.DANGEROUS_HTTP_METHODS.contains(methodInsnNode.name) ? ThreatResult.RiskLevel.HIGH : ThreatResult.RiskLevel.MEDIUM;

        String description = String.format("Command execution method: %s.%s", getSimpleClassName(methodInsnNode.owner), methodInsnNode.name);

        StringBuilder details = buildCommandMethodDetails(methodInsnNode, currentCommand);

        if (currentCommand != null) {
            risk = ThreatResult.RiskLevel.CRITICAL;
        }

        results.add(createThreatResult(risk, className, methodName, description, details.toString()));
    }

    private void handleSystemInfoMethod(MethodInsnNode methodInsnNode, String className, String methodName, List<ThreatResult> results) {
        results.add(createThreatResult(
                ThreatResult.RiskLevel.LOW, className, methodName,
                "System information access: " + methodInsnNode.name,
                "May be used for environment reconnaissance"
        ));
    }

    private StringBuilder buildCommandMethodDetails(MethodInsnNode methodInsnNode, String currentCommand) {
        StringBuilder details = new StringBuilder().append("Method: ").append(methodInsnNode.owner).append(".").append(methodInsnNode.name).append(methodInsnNode.desc);

        if (currentCommand != null) {
            details.append("\nPotential command: ").append(truncateString(currentCommand, 100));
        }

        return details;
    }
}