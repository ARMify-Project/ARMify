package armify.ui.views;

import armify.domain.EventBus;
import armify.domain.PeripheralAccess;
import armify.services.ProgramStorageService;
import armify.ui.components.AddPeripheralAccessDialog;
import armify.ui.components.PeripheralAccessTable;
import armify.ui.events.AnalysisCompleteEvent;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import resources.Icons;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class MMIOAddressView implements ViewComponent {
    private final ProgramStorageService storageService;
    private final EventBus eventBus;
    private final PluginTool tool;
    private final List<DockingAction> actions = new ArrayList<>();
    private final JPanel mainPanel;
    private final PeripheralAccessTable accessTable;
    private static final Icon EDIT_ICON = ResourceManager.loadImage("images/edit.gif");

    public MMIOAddressView(ProgramStorageService programStorageService, EventBus eventBus, PluginTool tool) {
        this.storageService = programStorageService;
        this.eventBus = eventBus;
        this.tool = tool;

        accessTable = new PeripheralAccessTable(tool);

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
                System.out.println("do refresh");
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

                AddPeripheralAccessDialog dlg = new AddPeripheralAccessDialog(
                        tool,
                        program,
                        null,
                        pa -> {
                            accessTable.addPeripheralAccess(pa);
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
                PeripheralAccess selected = accessTable.getSelectedEntry();
                if (selected == null || selected.getType() != PeripheralAccess.Type.custom) {
                    return;
                }

                AddPeripheralAccessDialog dlg = new AddPeripheralAccessDialog(
                        tool,
                        program,
                        selected,
                        pa -> {
                            accessTable.updatePeripheralAccess(modelRow, pa);
                            persist(program);
                        }
                );

                tool.showDialog(dlg);
            }

            @Override
            public boolean isEnabledForContext(ActionContext c) {
                PeripheralAccess sel = accessTable.getSelectedEntry();
                return sel != null && sel.getType() == PeripheralAccess.Type.custom
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
        storageService.saveMMIOAddresses(program, accessTable.getAllEntries());
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