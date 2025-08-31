package dev.mark.code.api.ui;

import dev.mark.code.api.Jar;
import dev.mark.code.api.model.ThreatResult;
import dev.mark.code.impl.CheckJar;
import dev.mark.code.impl.ThreatCheckerFactory;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@SuppressWarnings("FieldCanBeLocal")
public class UI {
    private JFrame frame;
    private JTextField fileField;
    private JCheckBox[] checkBoxes;
    private JTable resultsTable;
    private DefaultTableModel tableModel;
    private JProgressBar progressBar;
    private JLabel statusLabel;
    private JButton analyzeButton;
    private JTextArea detailsArea;
    private JSplitPane mainSplitPane;
    private JLabel statsLabel;

    private static final String[] TABLE_COLUMNS = {
            "Type", "Risk", "Class", "Method", "Description"
    };

    private static final Color PRIMARY_COLOR = new Color(41, 98, 255);
    private static final Color SUCCESS_COLOR = new Color(34, 197, 94);
    private static final Color WARNING_COLOR = new Color(251, 146, 60);
    private static final Color DANGER_COLOR = new Color(239, 68, 68);
    private static final Color CRITICAL_COLOR = new Color(147, 51, 234);
    private static final Color BACKGROUND_COLOR = new Color(248, 250, 252);
    private static final Color PANEL_COLOR = new Color(255, 255, 255);
    private static final Color BORDER_COLOR = new Color(226, 232, 240);

    public void mainUI() {
        SwingUtilities.invokeLater(this::createAndShowGUI);
    }

    private void createAndShowGUI() {
        setupLookAndFeel();
        setupFrame();
        createComponents();
        setupEventHandlers();

        frame.setVisible(true);
    }

    private void setupLookAndFeel() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

            UIManager.put("Panel.background", BACKGROUND_COLOR);
            UIManager.put("Button.arc", 8);
            UIManager.put("Component.arc", 8);
            UIManager.put("TextComponent.arc", 8);
        } catch (Exception ignored) {}
    }

    private void setupFrame() {
        frame = new JFrame("JAR Analyzer");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1500, 950);
        frame.setLocationRelativeTo(null);
        frame.setLayout(new BorderLayout());
        frame.getContentPane().setBackground(BACKGROUND_COLOR);

        try {
            frame.setIconImage(createIcon());
        } catch (Exception ignored) {}
    }

    private Image createIcon() {
        BufferedImage icon = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2 = icon.createGraphics();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        g2.setColor(PRIMARY_COLOR);
        g2.fillRoundRect(4, 4, 24, 24, 8, 8);

        g2.setColor(Color.WHITE);
        g2.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        FontMetrics fm = g2.getFontMetrics();
        String text = "J";
        int x = (32 - fm.stringWidth(text)) / 2;
        int y = (32 - fm.getHeight()) / 2 + fm.getAscent();
        g2.drawString(text, x, y);

        g2.dispose();
        return icon;
    }

    private void createComponents() {
        createTopPanel();
        createCenterPanel();
        createBottomPanel();
    }

    private void setupEventHandlers() {
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent windowEvent) {
                CheckJar.shutdown();
                System.exit(0);
            }
        });

        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showThreatDetails();
            }
        });
    }

    private void createTopPanel() {
        JPanel topPanel = new JPanel(new BorderLayout(0, 15));
        topPanel.setBorder(new EmptyBorder(20, 20, 20, 20));
        topPanel.setBackground(BACKGROUND_COLOR);

        topPanel.add(createFileSelectionPanel(), BorderLayout.NORTH);
        topPanel.add(createAnalysisOptionsPanel(), BorderLayout.CENTER);
        topPanel.add(createControlPanel(), BorderLayout.SOUTH);

        frame.add(topPanel, BorderLayout.NORTH);
    }

    private JPanel createFileSelectionPanel() {
        JPanel filePanel = new JPanel(new BorderLayout(10, 0));
        filePanel.setBackground(PANEL_COLOR);
        filePanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_COLOR, 1),
                new EmptyBorder(15, 15, 15, 15)
        ));

        JLabel titleLabel = new JLabel("Select JAR File");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16));
        titleLabel.setForeground(new Color(51, 65, 85));

        fileField = new JTextField();
        fileField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        fileField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_COLOR, 1),
                new EmptyBorder(8, 12, 8, 12)
        ));
        fileField.setPreferredSize(new Dimension(0, 40));

        JButton browseButton = createStyledButton("Browse", PRIMARY_COLOR);
        browseButton.setPreferredSize(new Dimension(120, 40));
        browseButton.addActionListener(e -> selectFile());

        JPanel topRow = new JPanel(new BorderLayout());
        topRow.setBackground(PANEL_COLOR);
        topRow.add(titleLabel, BorderLayout.WEST);

        JPanel inputRow = new JPanel(new BorderLayout(10, 0));
        inputRow.setBackground(PANEL_COLOR);
        inputRow.add(fileField, BorderLayout.CENTER);
        inputRow.add(browseButton, BorderLayout.EAST);

        filePanel.add(topRow, BorderLayout.NORTH);
        filePanel.add(Box.createVerticalStrut(10), BorderLayout.CENTER);
        filePanel.add(inputRow, BorderLayout.SOUTH);

        return filePanel;
    }

    private JPanel createAnalysisOptionsPanel() {
        JPanel checksPanel = new JPanel();
        checksPanel.setLayout(new BoxLayout(checksPanel, BoxLayout.Y_AXIS));
        checksPanel.setBackground(PANEL_COLOR);
        checksPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_COLOR, 1),
                new EmptyBorder(15, 15, 15, 15)
        ));

        JLabel titleLabel = new JLabel("Analysis Options");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16));
        titleLabel.setForeground(new Color(51, 65, 85));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        checksPanel.add(titleLabel);
        checksPanel.add(Box.createVerticalStrut(15));

        String[] checkNames = ThreatCheckerFactory.getAllDisplayNames();
        checkBoxes = new JCheckBox[checkNames.length];

        JPanel checkboxGrid = new JPanel(new GridLayout(2, 3, 15, 10));
        checkboxGrid.setBackground(PANEL_COLOR);

        for (int i = 0; i < checkNames.length; i++) {
            checkBoxes[i] = new JCheckBox(checkNames[i], true);
            checkBoxes[i].setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
            checkBoxes[i].setBackground(PANEL_COLOR);
            checkBoxes[i].setFocusPainted(false);
            checkboxGrid.add(checkBoxes[i]);
        }

        checksPanel.add(checkboxGrid);
        return checksPanel;
    }

    private JPanel createControlPanel() {
        JPanel controlPanel = new JPanel(new BorderLayout(0, 10));
        controlPanel.setBackground(BACKGROUND_COLOR);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 15, 0));
        buttonPanel.setBackground(BACKGROUND_COLOR);

        analyzeButton = createStyledButton("Analyze JAR File", PRIMARY_COLOR);
        analyzeButton.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 15));
        analyzeButton.setPreferredSize(new Dimension(220, 45));
        analyzeButton.addActionListener(e -> performAnalysis());

        JButton clearButton = createStyledButton("Clear Results", new Color(107, 114, 128));
        clearButton.setPreferredSize(new Dimension(140, 45));
        clearButton.addActionListener(e -> clearResults());

        JButton statsButton = createStyledButton("JAR Info", new Color(59, 130, 246));
        statsButton.setPreferredSize(new Dimension(120, 45));
        statsButton.addActionListener(e -> showJarStats());

        buttonPanel.add(analyzeButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(statsButton);

        statsLabel = new JLabel("No JAR loaded", SwingConstants.CENTER);
        statsLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 12));
        statsLabel.setForeground(new Color(107, 114, 128));

        controlPanel.add(buttonPanel, BorderLayout.CENTER);
        controlPanel.add(statsLabel, BorderLayout.SOUTH);

        return controlPanel;
    }

    private JButton createStyledButton(String text, Color bgColor) {
        JButton button = new JButton(text);
        button.setBackground(bgColor);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorderPainted(false);
        button.setOpaque(true);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));

        button.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                button.setBackground(bgColor.darker());
            }

            @Override
            public void mouseExited(MouseEvent e) {
                button.setBackground(bgColor);
            }
        });

        return button;
    }

    private void createCenterPanel() {
        createResultsTable();
        createDetailsPanel();

        JScrollPane tableScrollPane = new JScrollPane(resultsTable);
        tableScrollPane.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_COLOR, 1),
                BorderFactory.createTitledBorder(
                        BorderFactory.createEmptyBorder(),
                        "Threat Analysis Results",
                        TitledBorder.LEFT,
                        TitledBorder.TOP,
                        new Font(Font.SANS_SERIF, Font.BOLD, 14),
                        new Color(51, 65, 85)
                )
        ));
        tableScrollPane.getViewport().setBackground(Color.WHITE);

        JScrollPane detailsScrollPane = new JScrollPane(detailsArea);
        detailsScrollPane.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_COLOR, 1),
                BorderFactory.createTitledBorder(
                        BorderFactory.createEmptyBorder(),
                        "Threat Details",
                        TitledBorder.LEFT,
                        TitledBorder.TOP,
                        new Font(Font.SANS_SERIF, Font.BOLD, 14),
                        new Color(51, 65, 85)
                )
        ));
        detailsScrollPane.setPreferredSize(new Dimension(500, 200));
        detailsScrollPane.getViewport().setBackground(Color.WHITE);

        mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tableScrollPane, detailsScrollPane);
        mainSplitPane.setResizeWeight(0.6);
        mainSplitPane.setDividerLocation(900);
        mainSplitPane.setDividerSize(8);
        mainSplitPane.setBorder(new EmptyBorder(0, 20, 0, 20));

        frame.add(mainSplitPane, BorderLayout.CENTER);
    }

    private void createResultsTable() {
        tableModel = new DefaultTableModel(TABLE_COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        resultsTable = new JTable(tableModel);
        resultsTable.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        resultsTable.setRowHeight(35);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        resultsTable.setShowVerticalLines(false);
        resultsTable.setShowHorizontalLines(true);
        resultsTable.setGridColor(new Color(241, 245, 249));
        resultsTable.setSelectionBackground(new Color(239, 246, 255));
        resultsTable.setSelectionForeground(new Color(30, 64, 175));

        resultsTable.getTableHeader().setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        resultsTable.getTableHeader().setBackground(new Color(248, 250, 252));
        resultsTable.getTableHeader().setForeground(new Color(51, 65, 85));
        resultsTable.getTableHeader().setBorder(BorderFactory.createMatteBorder(0, 0, 2, 0, BORDER_COLOR));

        var columnModel = resultsTable.getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(150);
        columnModel.getColumn(1).setPreferredWidth(100);
        columnModel.getColumn(2).setPreferredWidth(250);
        columnModel.getColumn(3).setPreferredWidth(180);
        columnModel.getColumn(4).setPreferredWidth(400);

        columnModel.getColumn(1).setCellRenderer(new RiskCellRenderer());

        resultsTable.setAutoCreateRowSorter(true);
    }

    private void createDetailsPanel() {
        detailsArea = new JTextArea();
        detailsArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        detailsArea.setEditable(false);
        detailsArea.setBackground(Color.WHITE);
        detailsArea.setBorder(new EmptyBorder(15, 15, 15, 15));
        detailsArea.setText("Select a threat from the table to view detailed information...");
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        detailsArea.setForeground(new Color(71, 85, 105));
    }

    private void createBottomPanel() {
        JPanel bottomPanel = new JPanel(new BorderLayout(0, 8));
        bottomPanel.setBorder(new EmptyBorder(10, 20, 20, 20));
        bottomPanel.setBackground(BACKGROUND_COLOR);

        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setString("Ready to analyze");
        progressBar.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        progressBar.setPreferredSize(new Dimension(0, 25));
        progressBar.setBackground(Color.WHITE);
        progressBar.setForeground(PRIMARY_COLOR);
        progressBar.setBorder(BorderFactory.createLineBorder(BORDER_COLOR, 1));

        statusLabel = new JLabel("JAR Security Analyzer - Ready", SwingConstants.CENTER);
        statusLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        statusLabel.setForeground(new Color(107, 114, 128));

        bottomPanel.add(progressBar, BorderLayout.CENTER);
        bottomPanel.add(statusLabel, BorderLayout.SOUTH);

        frame.add(bottomPanel, BorderLayout.SOUTH);
    }

    private void selectFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("JAR Files (*.jar)", "jar"));
        chooser.setMultiSelectionEnabled(false);
        chooser.setDialogTitle("Select JAR File for Analysis");

        if (chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            File selectedFile = chooser.getSelectedFile();
            fileField.setText(selectedFile.getAbsolutePath());
            updateStatsLabel(selectedFile);
        }
    }

    private void updateStatsLabel(File file) {
        if (file != null && file.exists()) {
            double sizeMB = file.length() / (1024.0 * 1024.0);
            statsLabel.setText(String.format("Selected: %s (%.2f MB)", file.getName(), sizeMB));
        }
    }

    private void performAnalysis() {
        String filePath = fileField.getText().trim();
        if (filePath.isEmpty()) {
            showStyledMessage("Please select a JAR file first.", "No File Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        File file = new File(filePath);
        if (!file.exists()) {
            showStyledMessage("Selected file does not exist.", "File Not Found", JOptionPane.ERROR_MESSAGE);
            return;
        }

        clearResults();
        analyzeButton.setEnabled(false);
        progressBar.setIndeterminate(true);
        progressBar.setString("Initializing analysis...");

        boolean[] selectedChecks = new boolean[checkBoxes.length];
        for (int i = 0; i < checkBoxes.length; i++) {
            selectedChecks[i] = checkBoxes[i].isSelected();
        }

        CompletableFuture<List<ThreatResult>> analysisTask = CheckJar.performAllChecks(file, selectedChecks[0], selectedChecks[1], selectedChecks[2], selectedChecks[3], selectedChecks[4], this::updateProgress);

        analysisTask.whenComplete((results, throwable) -> SwingUtilities.invokeLater(() -> {
            analyzeButton.setEnabled(true);
            progressBar.setIndeterminate(false);
            progressBar.setValue(100);

            if (throwable != null) {
                handleAnalysisError(throwable);
            } else {
                handleAnalysisSuccess(results);
                updateJarStatsAfterAnalysis();
            }
        }));
    }

    private void showStyledMessage(String message, String title, int messageType) {
        UIManager.put("OptionPane.background", PANEL_COLOR);
        UIManager.put("Panel.background", PANEL_COLOR);
        JOptionPane.showMessageDialog(frame, message, title, messageType);
    }

    private void handleAnalysisError(Throwable throwable) {
        progressBar.setString("Analysis failed");
        progressBar.setForeground(DANGER_COLOR);
        statusLabel.setText("Error: " + throwable.getMessage());
        showStyledMessage("Analysis failed: " + throwable.getMessage(), "Analysis Error", JOptionPane.ERROR_MESSAGE);
    }

    private void handleAnalysisSuccess(List<ThreatResult> results) {
        displayResults(results);

        if (results.isEmpty()) {
            progressBar.setString("No threats detected");
            progressBar.setForeground(SUCCESS_COLOR);
            statusLabel.setText("Analysis complete - No threats found");
        } else {
            progressBar.setString("Analysis complete - Threats detected");
            progressBar.setForeground(WARNING_COLOR);
            statusLabel.setText(String.format("Analysis complete - %d potential threats detected", results.size()));
        }
    }

    private void updateJarStatsAfterAnalysis() {
        var stats = Jar.getJarStats();
        statsLabel.setText(String.format(
                "Analysis complete | Classes: %d | Files: %d | Failed: %d",
                ((Number) stats.get("totalClasses")).intValue(),
                ((Number) stats.get("totalFiles")).intValue(),
                ((Number) stats.get("failedClasses")).intValue()
        ));
    }

    private void updateProgress(String message) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setString(message);
            statusLabel.setText(message);
        });
    }

    private void displayResults(List<ThreatResult> results) {
        tableModel.setRowCount(0);

        for (ThreatResult result : results) {
            Object[] row = {
                    result.getType().getDisplayName(),
                    result.getRiskLevel().getDisplayName(),
                    getSimpleClassName(result.getClassName()),
                    result.getMethodName(),
                    result.getDescription()
            };
            tableModel.addRow(row);
        }

        if (!results.isEmpty()) {
            resultsTable.getRowSorter().toggleSortOrder(1);
        }
    }

    private void showThreatDetails() {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow < 0) {
            detailsArea.setText("Select a threat from the table to view detailed information...");
            return;
        }

        int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
        String className = (String) tableModel.getValueAt(modelRow, 2);
        String methodName = (String) tableModel.getValueAt(modelRow, 3);
        String description = (String) tableModel.getValueAt(modelRow, 4);
        String type = (String) tableModel.getValueAt(modelRow, 0);

        String details = "THREAT ANALYSIS\n" +
                "═══════════════════════════════════════\n\n" +
                "DETAILS\n" +
                "Type: " + type + "\n" +
                "Class: " + className + "\n" +
                "Method: " + methodName + "\n" +
                "Description: " + description + "\n\n";

        detailsArea.setText(details);
        detailsArea.setCaretPosition(0);
    }

    private void showJarStats() {
        if (Jar.classes.isEmpty()) {
            showStyledMessage("No JAR file has been loaded yet.", "No Data Available", JOptionPane.WARNING_MESSAGE);
            return;
        }

        var stats = Jar.getJarStats();
        var mainClasses = Jar.getMainClasses();

        StringBuilder statsText = new StringBuilder();
        statsText.append("JAR FILE INFORMATION\n");
        statsText.append("═══════════════════════════════════════\n\n");

        statsText.append("BASIC STATISTICS\n");
        statsText.append("Classes: ").append(stats.get("totalClasses")).append("\n");
        statsText.append("Files: ").append(stats.get("totalFiles")).append("\n");
        statsText.append("Failed Classes: ").append(stats.get("failedClasses")).append("\n");
        statsText.append("Manifest Entries: ").append(stats.get("manifestEntries")).append("\n\n");

        if (!mainClasses.isEmpty()) {
            statsText.append("ENTRY POINTS\n");
            mainClasses.forEach(main -> statsText.append("• ").append(main).append("\n"));
            statsText.append("\n");
        }

        @SuppressWarnings("unchecked")
        var packageStats = (Map<String, Integer>) stats.get("packageStats");
        if (!packageStats.isEmpty()) {
            statsText.append("📦 TOP PACKAGES\n");
            packageStats.entrySet().stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                    .limit(10)
                    .forEach(entry -> statsText.append("• ")
                            .append(entry.getKey())
                            .append(": ")
                            .append(entry.getValue())
                            .append(" classes\n"));
        }

        JTextArea textArea = new JTextArea(statsText.toString());
        textArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        textArea.setEditable(false);
        textArea.setBackground(Color.WHITE);
        textArea.setBorder(new EmptyBorder(15, 15, 15, 15));

        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(500, 400));
        scrollPane.setBorder(BorderFactory.createLineBorder(BORDER_COLOR, 1));

        JDialog dialog = new JDialog(frame, "JAR File Information", true);
        dialog.add(scrollPane);
        dialog.setSize(550, 450);
        dialog.setLocationRelativeTo(frame);
        dialog.setVisible(true);
    }

    private void clearResults() {
        tableModel.setRowCount(0);
        detailsArea.setText("Select a threat from the table to view detailed information...");
        progressBar.setValue(0);
        progressBar.setString("Ready to analyze");
        progressBar.setForeground(PRIMARY_COLOR);
        statusLabel.setText("JAR Security Analyzer - Ready");
    }

    private String getSimpleClassName(String fullClassName) {
        if (fullClassName == null) return "";
        int lastSlash = fullClassName.lastIndexOf('/');
        return lastSlash >= 0 ? fullClassName.substring(lastSlash + 1) : fullClassName;
    }

    private static class RiskCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int column) {

            Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (value instanceof String riskLevel) {
                Color backgroundColor = switch (riskLevel.toLowerCase()) {
                    case "critical" -> CRITICAL_COLOR;
                    case "high" -> DANGER_COLOR;
                    case "medium" -> WARNING_COLOR;
                    case "low" -> SUCCESS_COLOR;
                    default -> new Color(107, 114, 128);
                };

                if (!isSelected) {
                    setBackground(backgroundColor);
                    setForeground(Color.WHITE);
                    setFont(getFont().deriveFont(Font.BOLD, 12f));
                } else {
                    setBackground(table.getSelectionBackground());
                    setForeground(table.getSelectionForeground());
                }

                setOpaque(true);
                setHorizontalAlignment(SwingConstants.CENTER);
                setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
                setText(riskLevel);
            }
            return component;
        }
    }
}