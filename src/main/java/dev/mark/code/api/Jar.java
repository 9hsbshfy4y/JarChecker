package dev.mark.code.api;

import org.apache.commons.io.IOUtils;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipException;

public class Jar {

    public static final Map<String, byte[]> files = new ConcurrentHashMap<>();
    public static final List<ClassNode> classes = Collections.synchronizedList(new ArrayList<>());
    public static final Map<String, String> manifest = new ConcurrentHashMap<>();

    private static final Map<String, String> decompileCache = new ConcurrentHashMap<>();
    private static final Set<String> failedClasses = ConcurrentHashMap.newKeySet();

    private static final String MAIN_METHOD_DESCRIPTOR = "([Ljava/lang/String;)V";
    private static final int PUBLIC_STATIC_MODIFIERS = 0x0009;

    public static void loadJar(File file) throws IOException {
        clearCache();
        validateJarFile(file);

        try (JarFile jarFile = new JarFile(file)) {
            loadManifest(jarFile);
            loadEntries(jarFile);
        } catch (ZipException e) {
            throw new IOException("Invalid or corrupted JAR file: " + e.getMessage(), e);
        }
    }

    private static void validateJarFile(File file) throws IOException {
        if (!file.exists()) {
            throw new IOException("File does not exist: " + file.getAbsolutePath());
        }

        if (!file.canRead()) {
            throw new IOException("Cannot read file: " + file.getAbsolutePath());
        }

        if (!isJarFile(file)) {
            throw new IOException("Not a JAR file: " + file.getName());
        }

        if (file.length() == 0) {
            throw new IOException("Empty JAR file: " + file.getName());
        }
    }

    private static boolean isJarFile(File file) {
        return file.getName().toLowerCase().endsWith(".jar");
    }

    private static void loadManifest(JarFile jarFile) throws IOException {
        if (jarFile.getManifest() != null) {
            jarFile.getManifest().getMainAttributes().forEach((key, value) -> manifest.put(key.toString(), value.toString()));
        }
    }

    private static void loadEntries(JarFile jarFile) {
        Enumeration<JarEntry> entries = jarFile.entries();
        int processedEntries = 0;
        int totalEntries = jarFile.size();

        while (entries.hasMoreElements()) {
            JarEntry jarEntry = entries.nextElement();
            processedEntries++;

            if (!jarEntry.isDirectory()) {
                processJarEntry(jarFile, jarEntry, processedEntries, totalEntries);
            }
        }
    }

    private static void processJarEntry(JarFile jarFile, JarEntry jarEntry, int processedEntries, int totalEntries) {
        try (InputStream inputStream = jarFile.getInputStream(jarEntry)) {
            byte[] bytes = IOUtils.toByteArray(inputStream);
            processEntry(jarEntry.getName(), bytes);
        } catch (Exception e) {
            System.err.printf("Error processing entry %s (%d/%d): %s%n",
                    jarEntry.getName(), processedEntries, totalEntries, e.getMessage());
        }
    }

    private static void processEntry(String entryName, byte[] bytes) {
        if (entryName.endsWith(".class")) {
            processClassFile(entryName, bytes);
        } else {
            files.put(entryName, bytes);
        }
    }

    private static void processClassFile(String entryName, byte[] bytes) {
        try {
            ClassNode classNode = createClassNode(bytes);

            if (isValidClass(classNode)) {
                classes.add(classNode);
            } else {
                handleInvalidClass(entryName, bytes);
            }

        } catch (Exception e) {
            handleClassProcessingError(entryName, bytes, e);
        }
    }

    private static ClassNode createClassNode(byte[] bytes) {
        ClassNode classNode = new ClassNode();
        ClassReader classReader = new ClassReader(bytes);
        classReader.accept(classNode, ClassReader.EXPAND_FRAMES);
        return classNode;
    }

    private static void handleInvalidClass(String entryName, byte[] bytes) {
        System.err.println("Invalid class structure: " + entryName);
        failedClasses.add(entryName);
        files.put(entryName, bytes);
    }

    private static void handleClassProcessingError(String entryName, byte[] bytes, Exception e) {
        System.err.println("Error processing class " + entryName + ": " + e.getMessage());
        failedClasses.add(entryName);
        files.put(entryName, bytes);
    }

    private static boolean isValidClass(ClassNode classNode) {
        return classNode.name != null &&
                !classNode.name.isEmpty() &&
                classNode.methods != null;
    }

    public static void clearCache() {
        files.clear();
        classes.clear();
        manifest.clear();
        decompileCache.clear();
        failedClasses.clear();
    }

    public static Map<String, Object> getJarStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalClasses", classes.size());
        stats.put("totalFiles", files.size());
        stats.put("failedClasses", failedClasses.size());
        stats.put("manifestEntries", manifest.size());
        stats.put("packageStats", calculatePackageStats());
        return stats;
    }

    private static Map<String, Integer> calculatePackageStats() {
        Map<String, Integer> packageStats = new HashMap<>();
        for (ClassNode classNode : classes) {
            String packageName = getPackageName(classNode.name);
            packageStats.merge(packageName, 1, Integer::sum);
        }
        return packageStats;
    }

    public static List<String> getMainClasses() {
        List<String> mainClasses = new ArrayList<>();

        addManifestMainClass(mainClasses);
        addDiscoveredMainClasses(mainClasses);

        return mainClasses;
    }

    private static void addManifestMainClass(List<String> mainClasses) {
        String mainClass = manifest.get("Main-Class");
        if (mainClass != null && !mainClass.isEmpty()) {
            mainClasses.add(mainClass);
        }
    }

    private static void addDiscoveredMainClasses(List<String> mainClasses) {
        classes.stream().filter(Jar::hasMainMethod).map(classNode -> classNode.name).forEach(mainClasses::add);
    }

    private static boolean hasMainMethod(ClassNode classNode) {
        if (classNode.methods == null) return false;

        return classNode.methods.stream().anyMatch(Jar::isMainMethod);
    }

    private static boolean isMainMethod(MethodNode method) {
        return "main".equals(method.name) && MAIN_METHOD_DESCRIPTOR.equals(method.desc) && (method.access & PUBLIC_STATIC_MODIFIERS) == PUBLIC_STATIC_MODIFIERS;
    }

    private static String getPackageName(String className) {
        int lastSlash = className.lastIndexOf('/');
        return lastSlash > 0 ? className.substring(0, lastSlash) : "(default)";
    }
}