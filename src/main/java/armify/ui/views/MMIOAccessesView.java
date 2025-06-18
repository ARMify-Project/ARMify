package armify.ui.views;

import armify.domain.EventBus;
import armify.domain.MMIOAccessEntry;
import armify.services.ProgramAnalysisService;
import armify.services.ProgramStorageService;
import armify.ui.components.AddMMIOAccessDialog;
import armify.ui.components.MMIOAccessTable;
import armify.ui.events.AnalysisCompleteEvent;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class MMIOAccessesView implements ViewComponent {
    private final ProgramStorageService storageService;
    private final ProgramAnalysisService analysisService;
    private final EventBus eventBus;
    private final PluginTool tool;
    private final List<DockingAction> actions = new ArrayList<>();
    private final JPanel mainPanel;
    private final MMIOAccessTable accessTable;
    private static final Icon EDIT_ICON = ResourceManager.loadImage("images/edit.gif");

    public MMIOAccessesView(ProgramStorageService programStorageService, ProgramAnalysisService analysisService,
                            EventBus eventBus, PluginTool tool) {
        this.storageService = programStorageService;
        this.analysisService = analysisService;
        this.eventBus = eventBus;
        this.tool = tool;

        accessTable = new MMIOAccessTable(tool);

        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(accessTable, BorderLayout.CENTER);

        registerEventHandlers();
        buildActions();
    }

    private void buildActions() {
        actions.add(refreshDockingAction());
        actions.add(addDockingAction());
        actions.add(editDockingAction());
        actions.add(deleteDockingAction());
    }

    private DockingAction refreshDockingAction() {
        DockingAction refresh = new DockingAction("Refresh all", "ARMify Plugin") {
            @Override
            public void actionPerformed(ActionContext c) {
                Program program = currentProgram();
                if (program == null) {
                    Msg.showWarn(this, null, "No active program",
                            "Open a program before refreshing.");
                    return;
                }

                String message =
                        """
                                This will…
                                • delete all *scanned* MMIO-access rows
                                • keep your *custom* rows
                                • run a full rescan of the program, which can take some time
                                
                                Continue?""";

                int choice = OptionDialog.showYesNoDialog(
                        tool.getActiveWindow(),
                        "ARMify – Rescan Register Accesses", message);

                if (choice != OptionDialog.YES_OPTION) {
                    return;
                }

                // get custom entries
                List<MMIOAccessEntry> customAccesses = accessTable.getAllEntries().stream()
                        .filter(pa -> pa.getType() == MMIOAccessEntry.Type.custom)
                        .toList();

                // run analysis service
                List<MMIOAccessEntry> scannedAccesses;
                try {
                    scannedAccesses = analysisService.scanMMIOAccesses(program, TaskMonitor.DUMMY);
                } catch (CancelledException e) {
                    Msg.showInfo(this, null, "ARMify",
                            "Scan cancelled, table left unchanged.");
                    return;
                }

                // merge lists
                List<MMIOAccessEntry> mergedAccesses = new ArrayList<>(customAccesses);
                mergedAccesses.addAll(scannedAccesses);

                // update gui and store
                accessTable.setData(mergedAccesses);
                storageService.saveMMIOAccesses(program, mergedAccesses);
            }
        };
        refresh.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, "0ARMify"));
        refresh.setDescription("Refresh all scanned accesses");
        return refresh;
    }

    private DockingAction addDockingAction() {
        DockingAction add = new DockingAction("Add Custom MMIO Access", "ARMify Plugin") {
            @Override
            public void actionPerformed(ActionContext c) {
                Program program = currentProgram();
                if (program == null) {
                    return;
                }

                AddMMIOAccessDialog dlg = new AddMMIOAccessDialog(
                        tool,
                        program,
                        null,
                        pa -> {
                            accessTable.addMMIOAccess(pa);
                            persist(program);
                        }
                );

                tool.showDialog(dlg);
            }
        };
        add.setToolBarData(new ToolBarData(Icons.ADD_ICON, "0ARMify"));
        add.setDescription("Add custom access");
        return add;
    }

    private DockingAction editDockingAction() {
        DockingAction edit = new DockingAction("Edit Custom Access", "ARMify Plugin") {
            @Override
            public void actionPerformed(ActionContext c) {
                Program program = currentProgram();
                if (program == null) {
                    return;
                }
                int modelRow = accessTable.getSelectedModelRow();
                MMIOAccessEntry selected = accessTable.getSelectedEntry();
                if (selected == null || selected.getType() != MMIOAccessEntry.Type.custom) {
                    return;
                }

                AddMMIOAccessDialog dlg = new AddMMIOAccessDialog(
                        tool,
                        program,
                        selected,
                        pa -> {
                            accessTable.updateMMIOAccess(modelRow, pa);
                            persist(program);
                        }
                );

                tool.showDialog(dlg);
            }

            @Override
            public boolean isEnabledForContext(ActionContext c) {
                MMIOAccessEntry sel = accessTable.getSelectedEntry();
                return sel != null && sel.getType() == MMIOAccessEntry.Type.custom
                        && accessTable.getTable().getSelectedRowCount() == 1;
            }
        };
        edit.setToolBarData(new ToolBarData(EDIT_ICON, "0ARMify"));
        edit.setDescription("Edit selected custom access");
        return edit;
    }

    private DockingAction deleteDockingAction() {
        DockingAction delete = new DockingAction("Delete Row(s)", "ARMify Plugin") {
            @Override
            public void actionPerformed(ActionContext c) {
                int[] viewRows = accessTable.getTable().getSelectedRows();
                if (viewRows.length == 0) {
                    return;
                }

                int choice = OptionDialog.showYesNoDialog(
                        tool.getActiveWindow(),
                        "Delete Entries from Table",
                        "Delete " + viewRows.length + " selected row(s)?");

                if (choice != OptionDialog.YES_OPTION) {
                    return;
                }

                // 1. remove from table
                accessTable.deleteRows(viewRows);

                // 2. persist
                Program program = currentProgram();
                if (program != null) {
                    persist(program);
                }
            }

            @Override
            public boolean isEnabledForContext(ActionContext c) {
                return accessTable.getTable().getSelectedRowCount() >= 1;
            }
        };
        delete.setToolBarData(new ToolBarData(Icons.DELETE_ICON, "0ARMify"));
        delete.setDescription("Delete selected rows");
        return delete;
    }

    private void registerEventHandlers() {
        eventBus.subscribe(AnalysisCompleteEvent.class,
                evt -> SwingUtilities.invokeLater(() ->
                        accessTable.setData(evt.getAccesses())));
    }

    private Program currentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return (pm == null) ? null : pm.getCurrentProgram();
    }

    private void persist(Program program) {
        storageService.saveMMIOAccesses(program, accessTable.getAllEntries());
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
        accessTable.getTable().getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                tool.contextChanged(provider);
            }
        });
    }
}