package armify.ui.views;

import armify.domain.EventBus;
import armify.domain.MMIOAccessEntry;
import armify.services.ProgramAnalysisService;
import armify.services.ProgramStorageService;
import armify.ui.components.AddMMIOAccessDialog;
import armify.ui.components.MMIOAccessTable;
import armify.ui.events.*;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import docking.widgets.table.GTable;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import resources.ResourceManager;

import javax.swing.*;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.table.TableCellEditor;
import java.awt.BorderLayout;
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
        attachCheckboxListener();
    }

    private void buildActions() {
        actions.add(refreshDockingAction());
        actions.add(addDockingAction());
        actions.add(editDockingAction());
        actions.add(deleteDockingAction());
    }

    private void attachCheckboxListener() {
        TableCellEditor editor = accessTable.getTable().getDefaultEditor(Boolean.class);

        editor.addCellEditorListener(new CellEditorListener() {
            @Override
            public void editingStopped(ChangeEvent e) {
                Program program = currentProgram();
                if (program != null) {
                    persist(program);
                }
            }

            @Override
            public void editingCanceled(ChangeEvent e) {
            }
        });
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
                evt -> SwingUtilities.invokeLater(
                        () -> accessTable.setData(evt.getAccesses())
                )
        );

        eventBus.subscribe(ProgramChangedEvent.class,
                evt -> SwingUtilities.invokeLater(() -> {
                    Program prog = evt.program();
                    List<MMIOAccessEntry> rows = storageService.loadMMIOAccesses(prog);

                    accessTable.setData(rows);
                    reconcileWithListing();
                })
        );

        eventBus.subscribe(ListingFullSyncEvent.class,
                ev -> SwingUtilities.invokeLater(this::reconcileWithListing));

        eventBus.subscribe(ListingFunctionRenamedEvent.class,
                evt -> SwingUtilities.invokeLater(() -> handleFunctionRenamed(evt)));

        eventBus.subscribe(ListingFunctionAddedEvent.class,
                evt -> SwingUtilities.invokeLater(() -> handleFunctionAdded(evt)));

        eventBus.subscribe(ListingFunctionRemovedEvent.class,
                evt -> SwingUtilities.invokeLater(() -> handleFunctionRemoved(evt)));

        eventBus.subscribe(ListingCodeClearedEvent.class,
                evt -> SwingUtilities.invokeLater(() -> handleCodeCleared(evt)));

        eventBus.subscribe(ListingCodePatchedEvent.class,
                evt -> SwingUtilities.invokeLater(() -> handleCodePatched(evt)));
    }

    private void reconcileWithListing() {
        Program program = currentProgram();
        if (program == null) {
            return;
        }

        Listing listing = program.getListing();
        FunctionManager fm = program.getFunctionManager();

        List<MMIOAccessEntry> rows = accessTable.getAllEntries();
        List<Integer> rowsToDelete = new ArrayList<>();
        boolean changed = false;

        for (int modelIdx = 0; modelIdx < rows.size(); modelIdx++) {

            MMIOAccessEntry accessEntry = rows.get(modelIdx);
            Address ia = accessEntry.getInstructionAddress();
            if (ia == null) {
                continue;                       // custom row without address
            }

            Instruction instr = listing.getInstructionAt(ia);
            if (instr == null) {
                rowsToDelete.add(modelIdx);     // instruction vanished
                continue;
            }

            String text = instr.toString();
            Function fn = fm.getFunctionContaining(ia);
            String fnName = (fn != null ? fn.getName() : "<no func>");

            if (!text.equals(accessEntry.getInstructionString()) ||
                    !fnName.equals(accessEntry.getFunctionName())) {

                MMIOAccessEntry upd = new MMIOAccessEntry(
                        accessEntry.isInclude(), accessEntry.getType(), accessEntry.getMode(),
                        accessEntry.getConfidence(), ia, fnName, text, accessEntry.getRegisterAddress());

                accessTable.updateMMIOAccess(modelIdx, upd);
                changed = true;
            }
        }

        // delete stale rows (convert to view indices)
        if (!rowsToDelete.isEmpty()) {
            GTable table = accessTable.getTable();
            int[] viewIdx = rowsToDelete.stream()
                    .mapToInt(table::convertRowIndexToView)
                    .filter(i -> i >= 0)
                    .toArray();
            accessTable.deleteRows(viewIdx);
            changed = true;
        }

        if (changed) {
            persist(program);
        }
    }

    private void handleFunctionRenamed(ListingFunctionRenamedEvent evt) {
        Program program = currentProgram();
        if (program == null) {
            return;
        }

        Address start = evt.start();
        Address end = evt.end();
        String newName = evt.newName();

        boolean changed = false;
        List<MMIOAccessEntry> rows = accessTable.getAllEntries();
        for (int i = 0; i < rows.size(); i++) {
            MMIOAccessEntry accessEntry = rows.get(i);
            Address ia = accessEntry.getInstructionAddress();
            if (ia != null && ia.compareTo(start) >= 0 && ia.compareTo(end) <= 0) {
                MMIOAccessEntry updated = new MMIOAccessEntry(
                        accessEntry.isInclude(), accessEntry.getType(), accessEntry.getMode(), accessEntry.getConfidence(),
                        ia, newName, accessEntry.getInstructionString(), accessEntry.getRegisterAddress());
                accessTable.updateMMIOAccess(i, updated);
                changed = true;
            }
        }
        if (changed) persist(program);
    }

    private void handleFunctionAdded(ListingFunctionAddedEvent evt) {
        Program program = currentProgram();
        if (program == null) {
            return;
        }

        Address start = evt.start();
        Address end = evt.end();
        String newName = evt.name();

        boolean changed = false;
        List<MMIOAccessEntry> rows = accessTable.getAllEntries();
        for (int i = 0; i < rows.size(); i++) {
            MMIOAccessEntry accessEntry = rows.get(i);
            Address ia = accessEntry.getInstructionAddress();
            if (ia != null && ia.compareTo(start) >= 0 && ia.compareTo(end) <= 0
                    && "<no func>".equals(accessEntry.getFunctionName())) {

                MMIOAccessEntry updated = new MMIOAccessEntry(
                        accessEntry.isInclude(), accessEntry.getType(), accessEntry.getMode(), accessEntry.getConfidence(),
                        ia, newName, accessEntry.getInstructionString(), accessEntry.getRegisterAddress());
                accessTable.updateMMIOAccess(i, updated);
                changed = true;
            }
        }
        if (changed) persist(program);
    }

    private void handleFunctionRemoved(ListingFunctionRemovedEvent evt) {
        Program program = currentProgram();
        if (program == null) {
            return;
        }

        Address start = evt.start();
        Address end = evt.end();

        boolean changed = false;
        List<MMIOAccessEntry> rows = accessTable.getAllEntries();
        for (int i = 0; i < rows.size(); i++) {
            MMIOAccessEntry accessEntry = rows.get(i);
            Address ia = accessEntry.getInstructionAddress();
            if (ia != null && ia.compareTo(start) >= 0 && ia.compareTo(end) <= 0
                    && !"<no func>".equals(accessEntry.getFunctionName())) {

                MMIOAccessEntry updated = new MMIOAccessEntry(
                        accessEntry.isInclude(), accessEntry.getType(), accessEntry.getMode(), accessEntry.getConfidence(),
                        ia, "<no func>", accessEntry.getInstructionString(), accessEntry.getRegisterAddress());
                accessTable.updateMMIOAccess(i, updated);
                changed = true;
            }
        }

        if (changed) persist(program);
    }

    private void handleCodeCleared(ListingCodeClearedEvent evt) {
        Program program = currentProgram();
        if (program == null) {
            return;
        }

        AddressSet cleared = evt.clearedRange();
        if (cleared == null || cleared.isEmpty()) {
            return;
        }

        List<MMIOAccessEntry> rows = accessTable.getAllEntries();
        List<Integer> viewRows = new ArrayList<>();

        for (int modelIdx = 0; modelIdx < rows.size(); modelIdx++) {
            MMIOAccessEntry accessEntry = rows.get(modelIdx);
            Address ia = accessEntry.getInstructionAddress();
            if (ia == null || !cleared.contains(ia)) {
                continue;
            }
            int viewIdx = accessTable.getTable().convertRowIndexToView(modelIdx);
            if (viewIdx >= 0) {
                viewRows.add(viewIdx);
            }
        }

        if (!viewRows.isEmpty()) {
            accessTable.deleteRows(viewRows.stream().mapToInt(Integer::intValue).toArray());
            persist(program);
        }
    }

    private void handleCodePatched(ListingCodePatchedEvent evt) {
        Program program = currentProgram();
        if (program == null) {
            return;
        }

        AddressSet patched = evt.patchedRange();
        if (patched == null || patched.isEmpty()) {
            return;
        }

        Listing listing = program.getListing();
        FunctionManager fm = program.getFunctionManager();

        List<MMIOAccessEntry> rows = accessTable.getAllEntries();
        List<Integer> rowsToDelete = new ArrayList<>();
        boolean changed = false;

        for (int modelIdx = 0; modelIdx < rows.size(); modelIdx++) {
            MMIOAccessEntry e = rows.get(modelIdx);
            Address ia = e.getInstructionAddress();

            if (ia == null || !patched.contains(ia)) {
                continue;                               // row unaffected
            }

            Instruction instr = listing.getInstructionAt(ia);
            if (instr == null) {
                rowsToDelete.add(modelIdx);             // remember for later delete
                continue;
            }

            /* instruction still present → rebuild row if text or func changed */
            Function fn = fm.getFunctionContaining(ia);
            String name = (fn != null ? fn.getName() : "<no func>");
            String text = instr.toString();

            if (!name.equals(e.getFunctionName()) ||
                    !text.equals(e.getInstructionString())) {

                MMIOAccessEntry upd = new MMIOAccessEntry(
                        e.isInclude(), e.getType(), e.getMode(), e.getConfidence(),
                        ia, name, text, e.getRegisterAddress());

                accessTable.updateMMIOAccess(modelIdx, upd);
                changed = true;
            }
        }

        /* delete rows last (needs view indices) */
        if (!rowsToDelete.isEmpty()) {
            GTable table = accessTable.getTable();
            int[] viewIdx = rowsToDelete.stream()
                    .mapToInt(table::convertRowIndexToView)
                    .filter(i -> i >= 0)
                    .toArray();
            accessTable.deleteRows(viewIdx);
            changed = true;
        }

        if (changed) persist(program);
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