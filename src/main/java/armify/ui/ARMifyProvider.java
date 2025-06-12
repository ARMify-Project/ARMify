package armify.ui;

import armify.domain.EventBus;
import armify.services.MatchingEngine;
import armify.services.ProgramInitializationService;
import armify.ui.components.NavigationTree;
import armify.ui.events.LocationChangedEvent;
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

    private final CardLayout cardLayout = new CardLayout();
    private final JPanel viewContainer = new JPanel(cardLayout);
    private JPanel rootPanel;

    /* injected services */
    private final ProgramInitializationService programInitializationService;
    private final PluginTool tool;

    /* dynamic state */
    private Program currentProgram;
    private boolean initDone = false;      // per programme

    /* ------------------------------------------------------------------ */
    public ARMifyProvider(PluginTool tool,
                          String owner,
                          MatchingEngine eng,
                          ProgramInitializationService programInitializationService) {

        super(tool, "ARMify Plugin", owner);
        this.tool = tool;
        this.programInitializationService = programInitializationService;

        buildUI(eng);
        registerHandlers();

        setIcon(ResourceManager.loadImage("images/logo.png"));
        setDefaultWindowPosition(WindowPosition.WINDOW);
        setTitle("ARMify Plugin");
    }

    /* UI ---------------------------------------------------------------- */
    private void buildUI(MatchingEngine eng) {

        NavigationTree nav = new NavigationTree(eventBus);

        views.put(ViewType.MMIO_ADDRESSES, new MMIOAddressView(eventBus, tool));
        views.put(ViewType.CANDIDATE_GROUPS, new CandidateGroupsView(eng, eventBus));

        for (Map.Entry<ViewType, ViewComponent> e : views.entrySet()) {
            viewContainer.add(e.getValue().getComponent(), e.getKey().name());
        }
        cardLayout.show(viewContainer, ViewType.MMIO_ADDRESSES.name());

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                nav.getComponent(),
                viewContainer);
        split.setDividerLocation(165);

        rootPanel = new JPanel(new BorderLayout());
        rootPanel.add(split, BorderLayout.CENTER);
    }

    private void registerHandlers() {
        eventBus.subscribe(ViewSelectionEvent.class,
                ev -> cardLayout.show(viewContainer, ev.getViewType().name()));
    }

    public void setProgramReference(Program p) {
        this.currentProgram = p;
        this.initDone = false;     // reset for new programme
    }

    public void onLocationChanged(Program p, ProgramLocation loc) {
        if (p != null && loc != null) {
            eventBus.publish(new LocationChangedEvent(p, loc));
        }
    }

    @Override
    public void componentShown() {
        /* We intercept BEFORE showing any UI */
        if (currentProgram == null) {
            return;
        }
        if (initDone) {
            super.componentShown();   // normal repaint
            return;
        }

        /* 1 – immediately hide the placeholder window */
        setVisible(false);

        /* 2 – run initialisation (may pop up dialogs) */
        boolean ok = programInitializationService.ensureInitialised(tool, currentProgram, eventBus);

        if (ok) {
            initDone = true;
            /* 3 – show the fully prepared provider */
            setVisible(true);          // triggers a new componentShown()
        }
        /* if cancelled: remain hidden; user can reopen the menu later */
    }

    @Override
    public JComponent getComponent() {
        return rootPanel;
    }
}