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
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * “MMIO Addresses” view restored to the original column order,
 * single-click navigation and a GTableFilterPanel.
 */
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

        // Preferred column widths – keep narrow Include / Mode columns
        table.getColumnModel().getColumn(0).setPreferredWidth(60);  // Include
        table.getColumnModel().getColumn(1).setPreferredWidth(60);  // Mode
        table.getColumnModel().getColumn(2).setPreferredWidth(80);  // Confidence
        table.getColumnModel().getColumn(3).setPreferredWidth(100); // InstrAddr
        table.getColumnModel().getColumn(4).setPreferredWidth(140); // Function
        table.getColumnModel().getColumn(5).setPreferredWidth(140); // Instruction
        table.getColumnModel().getColumn(6).setPreferredWidth(100); // PeriphAddr
    }

    private void buildActions() {

        DockingAction merge = new DockingAction("Merge Rows", "ARMify Plugin") {

            @Override
            public void actionPerformed(ActionContext c) {
                System.out.println("do merge");
            }

            /* only show while MMIO card active */
            @Override
            public boolean isEnabledForContext(ActionContext c) {
                return table.getSelectedRowCount() > 1;
            }
        };

        merge.setToolBarData(new ToolBarData(Icons.ARROW_UP_LEFT_ICON, "0ARMify"));
        merge.setDescription("Merge selected MMIO rows");
        actions.add(merge);
    }

    private JPanel createTablePanel() {

        JPanel panel = new JPanel(new BorderLayout());

        // Toolbar with Add / Delete
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);

        JButton addButton = new JButton("Add");
        JButton deleteButton = new JButton("Delete");
        addButton.addActionListener(this::handleAddButton);
        deleteButton.addActionListener(this::handleDeleteButton);
        toolbar.add(addButton);
        toolbar.add(deleteButton);

        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        // Ghidra filter panel (ships with docking widgets)
        GTableFilterPanel<PeripheralAccess> filter =
                new GTableFilterPanel<>(table, tableModel);
        panel.add(filter, BorderLayout.SOUTH);

        return panel;
    }

    /* ------------------------------------------------------------------ */
    /* Toolbar actions                                                     */
    /* ------------------------------------------------------------------ */

    private void handleAddButton(ActionEvent e) {
        JOptionPane.showMessageDialog(mainPanel,
                "Add functionality not yet implemented");
    }

    private void handleDeleteButton(ActionEvent e) {

        int[] viewRows = table.getSelectedRows();
        if (viewRows.length == 0) {
            return;
        }

        int[] modelRows = new int[viewRows.length];
        for (int i = 0; i < viewRows.length; i++) {
            modelRows[i] = table.convertRowIndexToModel(viewRows[i]);
        }
        tableModel.removeRows(modelRows);
    }

    /* ------------------------------------------------------------------ */
    /* Event handling                                                      */
    /* ------------------------------------------------------------------ */

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
            extends GDynamicColumnTableModel<PeripheralAccess,
            List<PeripheralAccess>> {

        private final List<PeripheralAccess> rows = new ArrayList<>();
        private final PluginTool tool;

        AccessTableModel(PluginTool tool) {
            super(tool);
            this.tool = tool;
        }

        /* ---------- data API ---------- */

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

        /* ---------- GTable model basics ---------- */

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
            return "Include".equals(getColumnName(col));
        }

        @Override
        public void setValueAt(Object aValue, int row, int col) {
            if ("Include".equals(getColumnName(col)) &&
                    row < rows.size() && aValue instanceof Boolean b) {
                rows.get(row).setInclude(b);
                fireTableRowsUpdated(row, row);
            }
        }

        /* ---------- Column helper base ---------- */

        private abstract static class Column<T>
                extends AbstractDynamicTableColumn<PeripheralAccess,
                T,
                List<PeripheralAccess>> {

            private final String name;

            Column(String name) {
                this.name = name;
            }

            @Override
            public String getColumnName() {
                return name;
            }
        }

        /* ---------- Individual columns ---------- */

        private static class IncludeColumn extends Column<Boolean> {
            IncludeColumn() {
                super("Include");
            }

            @Override
            public Boolean getValue(PeripheralAccess r, Settings s,
                                    List<PeripheralAccess> d,
                                    ServiceProvider sp) {
                return r.isInclude();
            }

            @Override
            public int getColumnPreferredWidth() {
                return 60;
            }
        }

        private static class ModeColumn extends Column<String> {
            ModeColumn() {
                super("Mode");
            }

            @Override
            public String getValue(PeripheralAccess r, Settings s,
                                   List<PeripheralAccess> d,
                                   ServiceProvider sp) {
                return r.getMode().toString();
            }
        }

        private static class ConfidenceColumn extends Column<String> {
            ConfidenceColumn() {
                super("Confidence");
            }

            @Override
            public String getValue(PeripheralAccess r, Settings s,
                                   List<PeripheralAccess> d,
                                   ServiceProvider sp) {
                return r.getConfidence().toString();
            }
        }

        private static class InstrAddrColumn extends Column<Address> {
            InstrAddrColumn() {
                super("Instruction Address");
            }

            @Override
            public Address getValue(PeripheralAccess r, Settings s,
                                    List<PeripheralAccess> d,
                                    ServiceProvider sp) {
                return r.getInstructionAddress();
            }
        }

        private static class FunctionColumn extends Column<String> {
            FunctionColumn() {
                super("Function");
            }

            @Override
            public String getValue(PeripheralAccess r, Settings s,
                                   List<PeripheralAccess> d,
                                   ServiceProvider sp) {
                return r.getFunctionName();
            }
        }

        private static class InstructionColumn extends Column<String> {
            InstructionColumn() {
                super("Instruction");
            }

            @Override
            public String getValue(PeripheralAccess r, Settings s,
                                   List<PeripheralAccess> d,
                                   ServiceProvider sp) {
                return r.getInstructionString();
            }
        }

        private static class PeriphAddrColumn extends Column<Address> {
            PeriphAddrColumn() {
                super("Peripheral Address");
            }

            @Override
            public Address getValue(PeripheralAccess r, Settings s,
                                    List<PeripheralAccess> d,
                                    ServiceProvider sp) {
                return r.getPeripheralAddress();
            }
        }

        /* ---------- Navigation support ---------- */

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

                    RowObjectTableModel<PeripheralAccess> model =
                            (RowObjectTableModel<PeripheralAccess>)
                                    table.getModel();

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
