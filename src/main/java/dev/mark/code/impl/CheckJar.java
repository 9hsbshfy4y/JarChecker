package dev.mark.code.impl;

import dev.mark.code.api.Jar;
import dev.mark.code.api.model.ThreatResult;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

@SuppressWarnings("all")
public class CheckJar {

    private static final ExecutorService EXECUTOR = Executors.newCachedThreadPool();

    public static CompletableFuture<List<ThreatResult>> performAllChecks(
            File file,
            boolean checkUrl,
            boolean checkEncrypt,
            boolean checkWebConnect,
            boolean checkCommand,
            boolean checkSocket,
            Consumer<String> progressCallback) {

        return CompletableFuture.supplyAsync(() -> {
            try {
                loadJarWithProgress(file, progressCallback);
                CheckConfig config = new CheckConfig(checkUrl, checkEncrypt, checkWebConnect, checkCommand, checkSocket);
                List<ThreatResult> results = executeChecks(config, progressCallback);

                progressCallback.accept("Analysis complete! Found " + results.size() + " threats");
                return results;

            } catch (Exception e) {
                progressCallback.accept("Error during analysis: " + e.getMessage());
                e.printStackTrace();
                return new ArrayList<>();
            }
        }, EXECUTOR);
    }

    private static void loadJarWithProgress(File file, Consumer<String> progressCallback) throws Exception {
        progressCallback.accept("Loading JAR file...");
        Jar.loadJar(file);

        var stats = Jar.getJarStats();
        int totalClasses = ((Number) stats.get("totalClasses")).intValue();
        int totalFiles = ((Number) stats.get("totalFiles")).intValue();

        progressCallback.accept(String.format("Loaded %d classes, %d files", totalClasses, totalFiles));
    }

    private static List<ThreatResult> executeChecks(CheckConfig config, Consumer<String> progressCallback) {
        List<ThreatResult> allResults = new ArrayList<>();
        var checkerTypes = ThreatCheckerFactory.CheckerType.values();

        int totalChecks = (int) java.util.Arrays.stream(checkerTypes).filter(config::isEnabled).count();

        int completedChecks = 0;

        for (var checkerType : checkerTypes) {
            if (!config.isEnabled(checkerType)) {
                continue;
            }

            completedChecks++;
            progressCallback.accept(String.format("Performing %s (%d/%d)...",
                    checkerType.getDisplayName(), completedChecks, totalChecks));

            try {
                List<ThreatResult> results = performSingleCheck(checkerType);
                allResults.addAll(results);

                progressCallback.accept(String.format("Completed %s - found %d threats",
                        checkerType.getDisplayName(), results.size()));

            } catch (Exception e) {
                progressCallback.accept(String.format("Error in %s: %s",
                        checkerType.getDisplayName(), e.getMessage()));
            }
        }

        return allResults;
    }

    private static List<ThreatResult> performSingleCheck(ThreatCheckerFactory.CheckerType checkerType) {
        AbstractThreatChecker checker = ThreatCheckerFactory.getChecker(checkerType);
        return checker.performCheck(Jar.classes);
    }

    public static void shutdown() {
        EXECUTOR.shutdown();
    }
}