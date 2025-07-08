package armify.ui;

import armify.domain.EventBus;
import armify.services.MatchingEngine;
import armify.services.ProgramAnalysisService;
import armify.services.ProgramInitializationService;
import armify.services.ProgramStorageService;
import armify.ui.components.NavigationTree;
import armify.ui.events.*;
import armify.ui.views.*;
import armify.util.ProgramValidator;
import docking.WindowPosition;
import docking.widgets.OkDialog;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramLocation;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.*;
import java.util.EnumMap;
import java.util.Map;

import static ghidra.program.util.ProgramEvent.*;

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
    private NavigationTree nav;

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

    public boolean isInitDone() {
        return initDone;
    }

    public void registerInitialActions() {
        views.values().forEach(v -> v.installListeners(tool, this));
        addActionsFor(currentView);

        SwingUtilities.invokeLater(() -> tool.contextChanged(this));
    }

    private void addActionsFor(ViewType vt) {
        views.get(vt).getViewActions().forEach(this::addLocalAction);
    }

    private void removeActionsFor(ViewType vt) {
        views.get(vt).getViewActions().forEach(this::removeLocalAction);
    }

    private void buildUI() {

        nav = new NavigationTree(eventBus);

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
            tool.contextChanged(this);
            cardLayout.show(viewContainer, currentView.name());

            SwingUtilities.invokeLater(() -> nav.selectView(currentView));
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

    public void publishListingChangedEvent(DomainObjectChangedEvent domainObjectChangedEvent) {
        if (domainObjectChangedEvent == null) {
            return;
        }

        boolean sawCodeRemoved = false;
        boolean sawCodeAdded = false;
        AddressSet removedSet = new AddressSet();
        AddressSet addedSet = new AddressSet();

        for (DomainObjectChangeRecord domainObjectChangeRecord : domainObjectChangedEvent) {
            if (!(domainObjectChangeRecord instanceof ProgramChangeRecord programChangeRecord)) {
                continue;
            }

            switch (programChangeRecord.getEventType()) {
                case FUNCTION_ADDED -> {
                    Function fn = (Function) programChangeRecord.getObject();
                    if (fn != null) {
                        eventBus.publish(
                                new ListingFunctionAddedEvent(
                                        fn.getEntryPoint(),
                                        fn.getBody().getMaxAddress(),
                                        fn.getName()
                                )
                        );
                    }
                }

                case FUNCTION_REMOVED -> {
                    AddressSetView body = (AddressSetView) programChangeRecord.getOldValue();
                    if (body != null && !body.isEmpty()) {
                        eventBus.publish(new ListingFunctionRemovedEvent(body.getMinAddress(), body.getMaxAddress()));
                    }
                }

                case SYMBOL_RENAMED -> {
                    Symbol sym = (Symbol) programChangeRecord.getObject();
                    if (sym != null && sym.getSymbolType() == SymbolType.FUNCTION) {
                        Function fn = (Function) sym.getObject();
                        if (fn == null) {
                            return;
                        }

                        AddressSet functionAddressSet = (AddressSet) fn.getBody();

                        if (functionAddressSet != null && !functionAddressSet.isEmpty()) {
                            String oldName = (String) programChangeRecord.getOldValue();
                            String newName = sym.getName();
                            Address start = functionAddressSet.getMinAddress();
                            Address end = functionAddressSet.getMaxAddress();

                            eventBus.publish(new ListingFunctionRenamedEvent(start, end, oldName, newName));
                        }
                    }
                }

                case CODE_REMOVED -> {
                    sawCodeRemoved = true;
                    removedSet.addRange(programChangeRecord.getStart(), programChangeRecord.getEnd());
                }

                case CODE_ADDED -> {
                    sawCodeAdded = true;
                    addedSet.addRange(programChangeRecord.getStart(), programChangeRecord.getEnd());
                }

                case CODE_REPLACED -> {
                    sawCodeRemoved = true;
                    sawCodeAdded = true;
                    addedSet.addRange(programChangeRecord.getStart(), programChangeRecord.getEnd());
                }

                default -> { /* ignore everything else */ }
            }
        }

        if (sawCodeRemoved) {
            if (sawCodeAdded) {
                addedSet.union(removedSet);
                eventBus.publish(new ListingCodePatchedEvent(addedSet));
            } else {
                eventBus.publish(new ListingCodeClearedEvent(removedSet));
            }
        }
    }

    @Override
    public void componentShown() {
        // We intercept BEFORE showing any UI
        if (currentProgram == null) {
            return;
        }

        if (!ProgramValidator.isValid(currentProgram)) {
            OkDialog.showError(
                    "Unsupported Program",
                    "ARMifyPlugin supports only little-endian ARM binaries."
            );
            setVisible(false);
            return;
        }

        if (initDone) {
            super.componentShown();
            eventBus.publish(new ListingFullSyncEvent());
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