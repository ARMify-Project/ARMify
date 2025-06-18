package armify.ui.views;

import armify.domain.EventBus;
import armify.ui.components.PeripheralAccessTable;
import armify.ui.events.AnalysisCompleteEvent;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import resources.Icons;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class MMIOAddressView implements ViewComponent {
    private final EventBus eventBus;
    private final List<DockingAction> actions = new ArrayList<>();
    private final JPanel mainPanel;
    private final PeripheralAccessTable accessTable;

    public MMIOAddressView(EventBus eventBus, PluginTool tool) {
        this.eventBus = eventBus;

        accessTable = new PeripheralAccessTable(tool);

        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(accessTable, BorderLayout.CENTER);

        registerEventHandlers();
        buildActions();
    }

    /* ------------------------------------------------------------------ */
    /* Docking-actions                                                    */
    /* ------------------------------------------------------------------ */

    private void buildActions() {
        actions.add(refreshDockingAction());
        actions.add(addDockingAction());
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
                System.out.println("do add");
            }
        };
        add.setToolBarData(new ToolBarData(Icons.ADD_ICON, "0ARMify"));
        add.setDescription("Add custom access");
        return add;
    }

    private DockingAction deleteDockingAction() {
        DockingAction delete = new DockingAction("Delete Row(s)", "ARMify Plugin") {
            @Override
            public void actionPerformed(ActionContext c) {
                System.out.println("do delete");
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

    /* ------------------------------------------------------------------ */
    /* Event-wiring & provider helpers                                    */
    /* ------------------------------------------------------------------ */

    private void registerEventHandlers() {
        eventBus.subscribe(AnalysisCompleteEvent.class,
                evt -> SwingUtilities.invokeLater(() ->
                        accessTable.setData(evt.getAccesses())));
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