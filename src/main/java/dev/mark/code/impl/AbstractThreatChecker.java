package dev.mark.code.impl;

import dev.mark.code.api.model.ThreatResult;
import dev.mark.code.util.StringUtils;
import org.objectweb.asm.tree.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public abstract class AbstractThreatChecker {

    protected final ThreatResult.ThreatType threatType;

    protected AbstractThreatChecker(ThreatResult.ThreatType threatType) {
        this.threatType = threatType;
    }

    public final List<ThreatResult> performCheck(List<ClassNode> classes) {
        return classes.parallelStream().flatMap(classNode -> analyzeClass(classNode).stream()).collect(Collectors.toList());
    }

    private List<ThreatResult> analyzeClass(ClassNode classNode) {
        List<ThreatResult> results = new ArrayList<>();

        if (classNode.methods != null) {
            for (MethodNode methodNode : classNode.methods) {
                analyzeMethod(classNode, methodNode, results);
            }
        }

        return results;
    }

    protected abstract void analyzeMethod(ClassNode classNode, MethodNode methodNode, List<ThreatResult> results);

    protected void analyzeStringConstant(String value, String className, String methodName, List<ThreatResult> results) {}

    protected void analyzeMethodCall(MethodInsnNode methodInsnNode, String className, String methodName, String currentContext, List<ThreatResult> results) {}

    protected final ThreatResult createThreatResult(ThreatResult.RiskLevel riskLevel, String className,
                                                    String methodName, String description, String details) {
        return new ThreatResult(threatType, riskLevel, className, methodName, description, details);
    }

    protected final void analyzeInstructions(ClassNode classNode, MethodNode methodNode, List<ThreatResult> results) {
        if (methodNode.instructions == null) return;

        AbstractInsnNode[] instructions = methodNode.instructions.toArray();
        InstructionContext context = new InstructionContext();

        for (AbstractInsnNode instruction : instructions) {
            processInstruction(instruction, classNode, methodNode, context, results);
        }
    }

    private void processInstruction(AbstractInsnNode instruction, ClassNode classNode, MethodNode methodNode, InstructionContext context, List<ThreatResult> results) {
        switch (instruction) {
            case LdcInsnNode ldcNode -> processLdcInstruction(ldcNode, classNode, methodNode, context, results);
            case MethodInsnNode methodInsnNode -> analyzeMethodCall(methodInsnNode, classNode.name, methodNode.name, context.lastString, results);
            case IntInsnNode intInsnNode -> context.lastInteger = intInsnNode.operand;
            default -> {}
        }
    }

    private void processLdcInstruction(LdcInsnNode ldcNode, ClassNode classNode, MethodNode methodNode, InstructionContext context, List<ThreatResult> results) {
        if (ldcNode.cst instanceof String stringValue) {
            context.lastString = stringValue;
            analyzeStringConstant(stringValue, classNode.name, methodNode.name, results);
        } else if (ldcNode.cst instanceof Integer intValue) {
            context.lastInteger = intValue;
        }
    }

    protected final String getSimpleClassName(String fullClassName) {
        return StringUtils.getSimpleClassName(fullClassName);
    }

    protected final String truncateString(String str, int maxLength) {
        return StringUtils.truncateString(str, maxLength);
    }

    protected final boolean isPrivateIP(String ip) {
        return StringUtils.isPrivateIP(ip);
    }
}