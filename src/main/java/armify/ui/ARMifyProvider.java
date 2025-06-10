package armify.ui;

import armify.domain.EventBus;
import armify.domain.PeripheralAccess;
import armify.services.MatchingEngine;
import armify.services.ProgramAnalysisService;
import armify.ui.components.NavigationTree;
import armify.ui.events.*;
import armify.ui.views.*;
import armify.util.ProgramValidator;
import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.*;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Entry-point docking provider wiring the navigation tree to the two view
 * cards.  Unchanged except the MMIOAddressView now needs the tool for
 * GoTo-navigation, which was already passed in the constructor.
 */
public class ARMifyProvider extends ComponentProviderAdapter {

    private final ProgramAnalysisService analysisService;
    private final MatchingEngine matchingEngine;
    private final EventBus eventBus = new EventBus();

    private JPanel mainPanel;
    private CardLayout cardLayout;
    private JPanel viewContainer;
    private NavigationTree navigationTree;
    private Map<ViewType, ViewComponent> views = new EnumMap<>(ViewType.class);

    private Program currentProgram;

    public ARMifyProvider(PluginTool tool, String owner,
                          ProgramAnalysisService analysisService,
                          MatchingEngine matchingEngine) {
        super(tool, "ARMify Plugin", owner);
        this.analysisService = analysisService;
        this.matchingEngine = matchingEngine;

        initializeUI();
        registerEventHandlers();

        setIcon(ResourceManager.loadImage("images/logo.png"));
        setDefaultWindowPosition(WindowPosition.WINDOW);
        setTitle("ARMify Plugin");
        setVisible(false);
    }

    /* ------------------------------------------------------------------ */
    /* UI setup                                                            */
    /* ------------------------------------------------------------------ */

    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        navigationTree = new NavigationTree(eventBus);

        cardLayout = new CardLayout();
        viewContainer = new JPanel(cardLayout);

        // Updated MMIO view keeps the same constructor
        views.put(ViewType.MMIO_ADDRESSES,
                new MMIOAddressView(eventBus, tool));
        views.put(ViewType.CANDIDATE_GROUPS,
                new CandidateGroupsView(matchingEngine, eventBus));

        for (Map.Entry<ViewType, ViewComponent> entry : views.entrySet()) {
            viewContainer.add(entry.getValue().getComponent(),
                    entry.getKey().name());
        }

        viewContainer.add(createDefaultPanel(), "DEFAULT");
        cardLayout.show(viewContainer, "DEFAULT");

        JSplitPane splitPane =
                new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                        navigationTree.getComponent(),
                        viewContainer);
        splitPane.setDividerLocation(165);
        mainPanel.add(splitPane, BorderLayout.CENTER);
    }

    private JPanel createDefaultPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        panel.setBorder(BorderFactory.createTitledBorder("ARMify Plugin"));
        panel.add(new JLabel("Select a view from the navigation tree"));
        JButton selectButton = new JButton("Run Analysis");
        selectButton.addActionListener(e -> startAnalysisTask());
        panel.add(selectButton);
        return panel;
    }

    /* ------------------------------------------------------------------ */
    /* Event handling                                                      */
    /* ------------------------------------------------------------------ */

    private void registerEventHandlers() {
        eventBus.subscribe(ViewSelectionEvent.class, this::handleViewSelection);
    }

    private void handleViewSelection(ViewSelectionEvent event) {
        cardLayout.show(viewContainer, event.getViewType().name());
    }

    private void startAnalysisTask() {

        Task analysisTask = new Task("Scanning MMIO Accesses",
                false, true, false) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    monitor.setMessage(
                            "Analyzing program for peripheral accesses…");
                    List<PeripheralAccess> accesses =
                            analysisService.scanPeripheralAccesses(
                                    currentProgram, monitor);

                    SwingUtilities.invokeLater(() ->
                            eventBus.publish(
                                    new AnalysisCompleteEvent(accesses)));
                } catch (Exception ex) {
                    SwingUtilities.invokeLater(() ->
                            JOptionPane.showMessageDialog(mainPanel,
                                    "Analysis failed: " + ex.getMessage(),
                                    "Error", JOptionPane.ERROR_MESSAGE));
                }
            }
        };

        new TaskLauncher(analysisTask, tool.getActiveWindow());
    }

    /* ------------------------------------------------------------------ */
    /* Provider callbacks                                                  */
    /* ------------------------------------------------------------------ */

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    @Override
    public void componentShown() {
        if (!ProgramValidator.isValid(currentProgram)) {
            JOptionPane.showMessageDialog(getComponent(),
                    "ARMify Plugin supports only little-endian ARM binaries.",
                    "Unsupported Program", JOptionPane.ERROR_MESSAGE);
            setVisible(false);
        }
    }

    public void onLocationChanged(Program program, ProgramLocation location) {
        this.currentProgram = program;
        if (program != null && location != null) {
            eventBus.publish(new LocationChangedEvent(program, location));
        }
    }
}