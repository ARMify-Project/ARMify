package armify.ui;

import armify.domain.EventBus;
import armify.services.MatchingEngine;
import armify.services.ProgramAnalysisService;
import armify.services.ProgramInitializationService;
import armify.services.ProgramStorageService;
import armify.ui.components.NavigationTree;
import armify.ui.events.LocationChangedEvent;
import armify.ui.events.ProgramChangedEvent;
import armify.ui.events.ViewSelectionEvent;
import armify.ui.views.*;
import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.*;
import java.util.EnumMap;
import java.util.Map;

/**
 * Provider becomes visible only via Window → ARMify.  The first time it is
 * shown for a programme, the initialisation dialog is displayed; if the user
 * cancels, the provider hides itself and will ask again next time.
 */
public class ARMifyProvider extends ComponentProviderAdapter {

    private final EventBus eventBus = new EventBus();
    private final Map<ViewType, ViewComponent> views = new EnumMap<>(ViewType.class);
    private ViewType currentView = ViewType.MMIO_ACCESSES;

    private final CardLayout cardLayout = new CardLayout();
    private final JPanel viewContainer = new JPanel(cardLayout);
    private JPanel rootPanel;

    private final MatchingEngine matchingEngine;
    private final ProgramInitializationService programInitializationService;
    private final ProgramStorageService programStorageService;
    private final ProgramAnalysisService programAnalysisService;
    private final PluginTool tool;

    private Program currentProgram;
    private boolean initDone = false;

    public ARMifyProvider(PluginTool tool,
                          String owner,
                          MatchingEngine matchingEngine,
                          ProgramInitializationService programInitializationService,
                          ProgramStorageService programStorageService,
                          ProgramAnalysisService programAnalysisService) {

        super(tool, "ARMify Plugin", owner);
        this.tool = tool;
        this.matchingEngine = matchingEngine;
        this.programInitializationService = programInitializationService;
        this.programStorageService = programStorageService;
        this.programAnalysisService = programAnalysisService;

        buildUI();
        views.values().forEach(v -> v.installListeners(tool, this));
        registerHandlers();

        setIcon(ResourceManager.loadImage("images/logo.png"));
        setDefaultWindowPosition(WindowPosition.WINDOW);
        setTitle("ARMify Plugin");
    }

    public void registerInitialActions() {
        views.values().forEach(v -> v.installListeners(tool, this));
        addActionsFor(currentView);
    }

    private void addActionsFor(ViewType vt) {
        views.get(vt).getViewActions().forEach(this::addLocalAction);
    }

    private void removeActionsFor(ViewType vt) {
        views.get(vt).getViewActions().forEach(this::removeLocalAction);
    }

    private void buildUI() {

        NavigationTree nav = new NavigationTree(eventBus);

        views.put(
                ViewType.MMIO_ACCESSES,
                new MMIOAccessesView(programStorageService, programAnalysisService, eventBus, tool)
        );
        views.put(ViewType.CANDIDATE_GROUPS, new CandidateGroupsView(matchingEngine, eventBus, tool));

        for (Map.Entry<ViewType, ViewComponent> e : views.entrySet()) {
            viewContainer.add(e.getValue().getComponent(), e.getKey().name());
        }
        cardLayout.show(viewContainer, ViewType.MMIO_ACCESSES.name());
        nav.selectView(ViewType.MMIO_ACCESSES);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                nav.getComponent(),
                viewContainer);
        split.setDividerLocation(165);

        rootPanel = new JPanel(new BorderLayout());
        rootPanel.add(split, BorderLayout.CENTER);
    }

    private void registerHandlers() {
        eventBus.subscribe(ViewSelectionEvent.class, ev -> {

            ViewType newView = ev.getViewType();
            if (newView == currentView) {
                return;                       // nothing to do
            }

            removeActionsFor(currentView);    // 1. hide old buttons
            currentView = newView;            // 2. remember
            addActionsFor(currentView);       // 3. show new buttons
            cardLayout.show(viewContainer, currentView.name());
        });
    }

    public void setProgramReference(Program program) {
        if (program == currentProgram) {
            return;
        }

        this.currentProgram = program;
        this.initDone = false;

        eventBus.publish(new ProgramChangedEvent(program));
    }

    public void onLocationChanged(Program p, ProgramLocation loc) {
        if (p != null && loc != null) {
            eventBus.publish(new LocationChangedEvent(p, loc));
        }
    }

    @Override
    public void componentShown() {
        // We intercept BEFORE showing any UI
        if (currentProgram == null) {
            return;
        }
        if (initDone) {
            super.componentShown();
            return;
        }

        // immediately hide the placeholder window
        setVisible(false);

        // run initialisation (may pop up dialogs)
        boolean ok = programInitializationService.ensureInitialised(tool, currentProgram, eventBus);

        if (ok) {
            initDone = true;
            // show the fully prepared provider
            setVisible(true);          // triggers a new componentShown()
        }
        // if cancelled: remain hidden; user can reopen the menu later
    }

    @Override
    public JComponent getComponent() {
        return rootPanel;
    }
}