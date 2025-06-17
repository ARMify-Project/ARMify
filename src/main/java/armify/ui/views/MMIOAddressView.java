package armify.ui.views;

import armify.domain.EventBus;
import armify.domain.PeripheralAccess;
import armify.ui.events.AnalysisCompleteEvent;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.table.*;
import ghidra.app.services.GoToService;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import resources.Icons;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class MMIOAddressView implements ViewComponent {
    private final EventBus eventBus;
    private final List<DockingAction> actions = new ArrayList<>();
    private final JPanel mainPanel;
    private final AccessTableModel tableModel;
    private final GTable table;

    public MMIOAddressView(EventBus eventBus, PluginTool tool) {
        this.eventBus = eventBus;

        tableModel = new AccessTableModel(tool);
        table = new GTable(tableModel);
        setupTable();

        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(createTablePanel(), BorderLayout.CENTER);

        registerEventHandlers();
        buildActions();
    }

    private void setupTable() {

        table.setRowSelectionAllowed(true);
        table.setColumnSelectionAllowed(false);
        table.setAutoResizeMode(GTable.AUTO_RESIZE_ALL_COLUMNS);

        tableModel.installJumpListener(table);
    }

    private void buildActions() {
        DockingAction refreshDockingAction = refreshDockingAction();
        actions.add(refreshDockingAction);

        DockingAction addDockingAction = addDockingAction();
        actions.add(addDockingAction);

        DockingAction deleteDockingAction = deleteDockingAction();
        actions.add(deleteDockingAction);
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
                return table.getSelectedRowCount() >= 1;
            }
        };

        delete.setToolBarData(new ToolBarData(Icons.DELETE_ICON, "0ARMify"));
        delete.setDescription("Delete selected rows");
        return delete;
    }

    private JPanel createTablePanel() {

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        GTableFilterPanel<PeripheralAccess> filter = new GTableFilterPanel<>(table, tableModel);
        panel.add(filter, BorderLayout.SOUTH);

        return panel;
    }

    private void registerEventHandlers() {
        eventBus.subscribe(AnalysisCompleteEvent.class,
                evt -> SwingUtilities.invokeLater(() ->
                        tableModel.setData(evt.getAccesses())));
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
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                tool.contextChanged(provider);
            }
        });
    }

    /* ================================================================== */
    /* Table model (extends GDynamicColumnTableModel for filter support)  */
    /* ================================================================== */

    private static class AccessTableModel
            extends GDynamicColumnTableModel<PeripheralAccess, List<PeripheralAccess>> {
        private final List<PeripheralAccess> rows = new ArrayList<>();
        private final PluginTool tool;

        AccessTableModel(PluginTool tool) {
            super(tool);
            this.tool = tool;
        }

        void setData(List<PeripheralAccess> newRows) {
            rows.clear();
            rows.addAll(newRows);
            fireTableDataChanged();
        }

        void removeRows(int[] modelRows) {
            java.util.Arrays.sort(modelRows);
            for (int i = modelRows.length - 1; i >= 0; i--) {
                rows.remove(modelRows[i]);
            }
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public List<PeripheralAccess> getModelData() {
            return rows;
        }

        @Override
        public List<PeripheralAccess> getDataSource() {
            return rows;
        }

        @Override
        public String getName() {
            return "Peripheral Accesses";
        }

        /* ---------- Column definitions ---------- */

        @Override
        protected TableColumnDescriptor<PeripheralAccess>
        createTableColumnDescriptor() {

            TableColumnDescriptor<PeripheralAccess> d =
                    new TableColumnDescriptor<>();

            d.addVisibleColumn(new IncludeColumn());
            d.addVisibleColumn(new GainColumn());
            d.addVisibleColumn(new TypeColumn());
            d.addVisibleColumn(new ModeColumn());
            d.addVisibleColumn(new ConfidenceColumn());
            d.addVisibleColumn(new InstrAddrColumn());
            d.addVisibleColumn(new FunctionColumn());
            d.addVisibleColumn(new InstructionColumn());
            d.addVisibleColumn(new PeriphAddrColumn());
            return d;
        }

        /* Only “Include” is editable */
        @Override
        public boolean isCellEditable(int row, int col) {
            return "Incl.".equals(getColumnName(col));
        }

        @Override
        public void setValueAt(Object aValue, int row, int col) {
            if ("Incl.".equals(getColumnName(col)) &&
                    row < rows.size() && aValue instanceof Boolean b) {
                rows.get(row).setInclude(b);
                fireTableRowsUpdated(row, row);
            }
        }

        private abstract static class Column<T>
                extends AbstractDynamicTableColumn<PeripheralAccess, T, List<PeripheralAccess>> {
            private final String name;

            Column(String name) {
                this.name = name;
            }

            @Override
            public String getColumnName() {
                return name;
            }
        }

        private static class IncludeColumn extends Column<Boolean> {
            IncludeColumn() {
                super("Incl.");
            }

            @Override
            public Boolean getValue(PeripheralAccess r, Settings s, List<PeripheralAccess> d, ServiceProvider sp) {
                return r.isInclude();
            }

            @Override
            public String getColumnDescription() {
                return "Include";
            }
        }

        private static class GainColumn extends Column<String> {
            GainColumn() {
                super("Gain");
            }

            @Override
            public String getValue(PeripheralAccess r, Settings s, List<PeripheralAccess> d, ServiceProvider sp) {
                if (r.isInclude()) return "0";
                return "";
            }

            @Override
            public String getColumnDescription() {
                return "Gain";
            }
        }

        private static class TypeColumn extends Column<String> {
            TypeColumn() {
                super("Type");
            }

            @Override
            public String getValue(PeripheralAccess r, Settings s, List<PeripheralAccess> d, ServiceProvider sp) {
                return r.getType().toString();
            }

            @Override
            public String getColumnDescription() {
                return "Type";
            }
        }

        private static class ModeColumn extends Column<String> {
            ModeColumn() {
                super("Mode");
            }

            @Override
            public String getValue(PeripheralAccess r, Settings s, List<PeripheralAccess> d, ServiceProvider sp) {
                return r.getMode().toString();
            }

            @Override
            public String getColumnDescription() {
                return "Mode";
            }
        }

        private static class ConfidenceColumn extends Column<String> {
            ConfidenceColumn() {
                super("Conf.");
            }

            @Override
            public String getValue(PeripheralAccess r, Settings s, List<PeripheralAccess> d, ServiceProvider sp) {
                return r.getConfidence().toString();
            }

            @Override
            public String getColumnDescription() {
                return "Confidence";
            }
        }

        private static class InstrAddrColumn extends Column<Address> {
            InstrAddrColumn() {
                super("Inst. Addr.");
            }

            @Override
            public Address getValue(PeripheralAccess r, Settings s, List<PeripheralAccess> d, ServiceProvider sp) {
                return r.getInstructionAddress();
            }

            @Override
            public String getColumnDescription() {
                return "Instruction Address";
            }
        }

        private static class FunctionColumn extends Column<String> {
            FunctionColumn() {
                super("Func.");
            }

            @Override
            public String getValue(PeripheralAccess r, Settings s, List<PeripheralAccess> d, ServiceProvider sp) {
                return r.getFunctionName();
            }

            @Override
            public String getColumnDescription() {
                return "Function";
            }
        }

        private static class InstructionColumn extends Column<String> {
            InstructionColumn() {
                super("Instr.");
            }

            @Override
            public String getValue(PeripheralAccess r, Settings s, List<PeripheralAccess> d, ServiceProvider sp) {
                return r.getInstructionString();
            }

            @Override
            public String getColumnDescription() {
                return "Instruction";
            }
        }

        private static class PeriphAddrColumn extends Column<Address> {
            PeriphAddrColumn() {
                super("Peri. Addr.");
            }

            @Override
            public Address getValue(PeripheralAccess r, Settings s, List<PeripheralAccess> d, ServiceProvider sp) {
                return r.getPeripheralAddress();
            }

            @Override
            public String getColumnDescription() {
                return "Peripheral Address";
            }
        }

        void installJumpListener(JTable table) {
            table.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {

                    if (SwingUtilities.isRightMouseButton(e) ||
                            e.getClickCount() != 1) {
                        return;
                    }

                    int viewRow = table.rowAtPoint(e.getPoint());
                    int viewCol = table.columnAtPoint(e.getPoint());
                    if (viewRow < 0 || viewCol < 0) {
                        return;
                    }

                    String colName = table.getColumnName(viewCol);
                    if (!Set.of("Instruction Address", "Instruction",
                            "Peripheral Address").contains(colName)) {
                        return;
                    }

                    RowObjectTableModel<PeripheralAccess> model = AccessTableModel.this;

                    PeripheralAccess entry =
                            model.getRowObject(
                                    table.convertRowIndexToModel(viewRow));

                    Address dest = "Peripheral Address".equals(colName)
                            ? entry.getPeripheralAddress()
                            : entry.getInstructionAddress();

                    goTo(dest);
                }
            });
        }

        private void goTo(Address addr) {
            GoToService svc = tool.getService(GoToService.class);
            if (svc != null) {
                svc.goTo(addr);
            } else {
                Msg.showWarn(this, null,
                        "Navigation service missing",
                        "Cannot navigate to " + addr);
            }
        }
    }
}
