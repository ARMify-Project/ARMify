package armify.ui.views;

import armify.domain.EventBus;
import armify.services.MatchingEngine;
import armify.ui.events.*;

import javax.swing.*;
import java.awt.*;

public class CandidateGroupsView implements ViewComponent {
    private final MatchingEngine matchingEngine;
    private final EventBus eventBus;
    private final JPanel mainPanel;

    public CandidateGroupsView(MatchingEngine matchingEngine, EventBus eventBus) {
        this.matchingEngine = matchingEngine;
        this.eventBus = eventBus;

        mainPanel = new JPanel(new BorderLayout());
        initializeUI();
        registerEventHandlers();
    }

    private void initializeUI() {
        // Create main layout
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        // Left side - address table
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(BorderFactory.createTitledBorder("Selected Addresses"));
        leftPanel.add(new JLabel("Address table (TODO)", SwingConstants.CENTER), BorderLayout.CENTER);

        // Right side - controls and group tree
        JPanel rightPanel = new JPanel(new BorderLayout());

        // Group tree
        JPanel treePanel = new JPanel(new BorderLayout());
        treePanel.setBorder(BorderFactory.createTitledBorder("Device Groups"));
        treePanel.add(new JLabel("Group tree (TODO)", SwingConstants.CENTER), BorderLayout.CENTER);

        // Controls
        JPanel controlPanel = createControlPanel();

        rightPanel.add(treePanel, BorderLayout.CENTER);
        rightPanel.add(controlPanel, BorderLayout.SOUTH);

        splitPane.setLeftComponent(leftPanel);
        splitPane.setRightComponent(rightPanel);
        splitPane.setDividerLocation(400);

        mainPanel.add(splitPane, BorderLayout.CENTER);
    }

    private JPanel createControlPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        // Tolerance slider
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(5, 5, 5, 5);
        panel.add(new JLabel("Tolerance:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        JSlider toleranceSlider = new JSlider(0, 20, 5);
        panel.add(toleranceSlider, gbc);

        // Buttons
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.add(new JButton("Reload"));
        buttonPanel.add(new JButton("Export"));
        buttonPanel.add(new JButton("Apply"));
        buttonPanel.add(new JButton("Compare..."));
        panel.add(buttonPanel, gbc);

        // Status
        gbc.gridy = 2;
        panel.add(new JLabel("Status: Ready"), gbc);

        return panel;
    }

    private void registerEventHandlers() {
        eventBus.subscribe(AnalysisCompleteEvent.class, this::handleAnalysisComplete);
    }

    private void handleAnalysisComplete(AnalysisCompleteEvent event) {
        // TODO: Update view with analysis results
        SwingUtilities.invokeLater(() -> {
            // Update UI components
        });
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
}
