package armify.ui.views;

import armify.domain.EventBus;
import armify.domain.MMIOAccessEntry;
import armify.domain.RegisterEntry;
import armify.services.MatchingEngine;
import armify.ui.components.RegisterTable;
import armify.ui.events.*;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import resources.Icons;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;

public class CandidateGroupsView implements ViewComponent {
    private final MatchingEngine matchingEngine;
    private final EventBus eventBus;
    private final PluginTool tool;
    private final List<DockingAction> actions = new ArrayList<>();
    private final JPanel mainPanel;
    private final RegisterTable registerTable;

    public CandidateGroupsView(MatchingEngine matchingEngine, EventBus eventBus, PluginTool tool) {
        this.matchingEngine = matchingEngine;
        this.eventBus = eventBus;
        this.tool = tool;

        registerTable = new RegisterTable(tool);

        mainPanel = new JPanel(new BorderLayout());
        initializeUI();
        registerEventHandlers();
        buildActions();
    }

    private void buildActions() {
        DockingAction export = new DockingAction("Export Groups", "ARMify Plugin") {

            @Override
            public void actionPerformed(docking.ActionContext c) {
                System.out.println("do export");
            }

            @Override
            public boolean isEnabledForContext(docking.ActionContext c) {
                return true;
            }
        };

        export.setToolBarData(new ToolBarData(Icons.ADD_ICON, "0ARMify"));
        actions.add(export);
    }

    private void initializeUI() {
        // Create main layout
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // Top side - address table
        JPanel topPanel = new JPanel(new BorderLayout());
        Border titledBorder = BorderFactory.createTitledBorder("Included Register Addresses");
        Border paddingBorder = BorderFactory.createEmptyBorder(5, 0, 0, 0);
        topPanel.setBorder(BorderFactory.createCompoundBorder(titledBorder, paddingBorder));
        topPanel.add(registerTable, BorderLayout.CENTER);

        // Bottom side - controls and group tree
        JPanel bottomPanel = new JPanel(new BorderLayout());

        // Group tree
        JPanel treePanel = new JPanel(new BorderLayout());
        treePanel.setBorder(BorderFactory.createTitledBorder("Device Groups"));
        treePanel.add(new JLabel("Group tree (TODO)", SwingConstants.CENTER), BorderLayout.CENTER);

        // Controls
        JPanel controlPanel = createControlPanel();

        bottomPanel.add(treePanel, BorderLayout.CENTER);
        bottomPanel.add(controlPanel, BorderLayout.SOUTH);

        splitPane.setTopComponent(topPanel);
        splitPane.setBottomComponent(bottomPanel);
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
        eventBus.subscribe(MMIOAccessTableChangedEvent.class, this::handleMMIOAccessTableChanged);
    }

    private void handleMMIOAccessTableChanged(MMIOAccessTableChangedEvent event) {
        List<RegisterEntry> registerEntries = new ArrayList<>();
        Set<Address> seen = new HashSet<>();

        for (MMIOAccessEntry mmioAccessEntry : event.entries()) {
            Address addr = mmioAccessEntry.getRegisterAddress();

            if (mmioAccessEntry.isInclude()) {
                if (seen.add(addr)) {
                    registerEntries.add(
                            new RegisterEntry(addr, null, null, null)
                    );
                }
            }
        }
        registerTable.setData(registerEntries);
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    @Override
    public List<DockingAction> getViewActions() {
        return actions;
    }

    @Override
    public void installListeners(PluginTool tool, ComponentProviderAdapter provider) {

    }
}
