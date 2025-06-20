package armify.ui.components;

import armify.domain.MMIOAccessEntry;
import docking.widgets.table.*;
import ghidra.app.services.GoToService;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

public class MMIOAccessTable extends JPanel {

    private final AccessTableModel tableModel;
    private final GTable table;

    public MMIOAccessTable(PluginTool tool) {
        super(new BorderLayout());

        tableModel = new AccessTableModel(tool);
        table = new GTable(tableModel);

        // Basic setup
        table.setRowSelectionAllowed(true);
        table.setColumnSelectionAllowed(false);
        table.setAutoResizeMode(GTable.AUTO_RESIZE_ALL_COLUMNS);

        tableModel.installJumpListener(table);

        add(new JScrollPane(table), BorderLayout.CENTER);

        GTableFilterPanel<MMIOAccessEntry> filter =
                new GTableFilterPanel<>(table, tableModel);
        add(filter, BorderLayout.SOUTH);
    }

    public void setData(List<MMIOAccessEntry> rows) {
        tableModel.setData(rows);
    }

    public GTable getTable() {
        return table;
    }

    public void addMMIOAccess(MMIOAccessEntry pa) {
        tableModel.addRow(pa);
    }

    public void updateMMIOAccess(int modelRow, MMIOAccessEntry pa) {
        tableModel.updateRow(modelRow, pa);
    }

    public int getSelectedModelRow() {
        int viewIdx = table.getSelectedRow();
        return (viewIdx < 0) ? -1 : table.convertRowIndexToModel(viewIdx);
    }

    public MMIOAccessEntry getSelectedEntry() {
        int modelRow = getSelectedModelRow();
        return (modelRow < 0) ? null : tableModel.getRowObject(modelRow);
    }

    public java.util.List<MMIOAccessEntry> getAllEntries() {
        return new java.util.ArrayList<>(tableModel.rows);   // defensive copy
    }

    public void deleteRows(int[] viewRows) {
        if (viewRows == null || viewRows.length == 0) {
            return;
        }

        // convert to model indices
        int[] modelIdx = java.util.Arrays.stream(viewRows)
                .map(table::convertRowIndexToModel)
                .toArray();
        tableModel.removeRows(modelIdx);
    }

    private static class AccessTableModel
            extends GDynamicColumnTableModel<MMIOAccessEntry, List<MMIOAccessEntry>> {

        private final List<MMIOAccessEntry> rows = new ArrayList<>();
        private final PluginTool tool;

        AccessTableModel(PluginTool tool) {
            super(tool);
            this.tool = tool;
        }

        void setData(List<MMIOAccessEntry> newRows) {
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

        void addRow(MMIOAccessEntry pa) {
            rows.add(pa);
            fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
        }

        void updateRow(int modelRow, MMIOAccessEntry pa) {
            rows.set(modelRow, pa);
            fireTableRowsUpdated(modelRow, modelRow);
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public List<MMIOAccessEntry> getModelData() {
            return rows;
        }

        @Override
        public List<MMIOAccessEntry> getDataSource() {
            return rows;
        }

        @Override
        public String getName() {
            return "MMIO Accesses";
        }

        @Override
        protected TableColumnDescriptor<MMIOAccessEntry>
        createTableColumnDescriptor() {

            TableColumnDescriptor<MMIOAccessEntry> d =
                    new TableColumnDescriptor<>();

            d.addVisibleColumn(new RegisterAddrColumn());
            d.addVisibleColumn(new GainColumn());
            d.addVisibleColumn(new TypeColumn());
            d.addVisibleColumn(new ModeColumn());
            d.addVisibleColumn(new ConfidenceColumn());
            d.addVisibleColumn(new InstrAddrColumn());
            d.addVisibleColumn(new FunctionColumn());
            d.addVisibleColumn(new InstructionColumn());
            d.addVisibleColumn(new IncludeColumn());

            return d;
        }

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
                extends AbstractDynamicTableColumn<MMIOAccessEntry, T, List<MMIOAccessEntry>> {
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
            public Boolean getValue(MMIOAccessEntry r, Settings s,
                                    List<MMIOAccessEntry> d, ServiceProvider sp) {
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
            public String getValue(MMIOAccessEntry r, Settings s,
                                   List<MMIOAccessEntry> d, ServiceProvider sp) {
                return r.isInclude() ? "0" : "";
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
            public String getValue(MMIOAccessEntry r, Settings s,
                                   List<MMIOAccessEntry> d, ServiceProvider sp) {
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
            public String getValue(MMIOAccessEntry r, Settings s,
                                   List<MMIOAccessEntry> d, ServiceProvider sp) {
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
            public String getValue(MMIOAccessEntry r, Settings s,
                                   List<MMIOAccessEntry> d, ServiceProvider sp) {
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
            public Address getValue(MMIOAccessEntry r, Settings s,
                                    List<MMIOAccessEntry> d, ServiceProvider sp) {
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
            public String getValue(MMIOAccessEntry r, Settings s,
                                   List<MMIOAccessEntry> d, ServiceProvider sp) {
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
            public String getValue(MMIOAccessEntry r, Settings s,
                                   List<MMIOAccessEntry> d, ServiceProvider sp) {
                return r.getInstructionString();
            }

            @Override
            public String getColumnDescription() {
                return "Instruction";
            }
        }

        private static class RegisterAddrColumn extends Column<Address> {
            RegisterAddrColumn() {
                super("Reg. Addr.");
            }

            @Override
            public Address getValue(MMIOAccessEntry r, Settings s,
                                    List<MMIOAccessEntry> d, ServiceProvider sp) {
                return r.getRegisterAddress();
            }

            @Override
            public String getColumnDescription() {
                return "Register Address";
            }
        }

        void installJumpListener(JTable table) {
            table.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (SwingUtilities.isRightMouseButton(e) || e.getClickCount() != 1) {
                        return;                                         // ignore right & double clicks
                    }

                    int viewRow = table.rowAtPoint(e.getPoint());
                    int viewCol = table.columnAtPoint(e.getPoint());
                    if (viewRow < 0 || viewCol < 0) {                   // outside table
                        return;
                    }

                    /* Grab the *displayed* value and navigate only if it's an Address */
                    Object cellValue = table.getValueAt(viewRow, viewCol);
                    if (!(cellValue instanceof Address dest)) {
                        return;                                         // non-address cell
                    }

                    goTo(dest);                                         // jump in CodeBrowser
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