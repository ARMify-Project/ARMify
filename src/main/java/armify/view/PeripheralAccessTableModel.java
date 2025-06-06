package armify.view;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.GDynamicColumnTableModel;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;

/**
 * Lightweight table-model: holds pre-computed rows supplied by the
 * controller.  No program-scanning logic lives here.
 */
public class PeripheralAccessTableModel
        extends GDynamicColumnTableModel<PeripheralAccessEntry,
        List<PeripheralAccessEntry>> {

    private final List<PeripheralAccessEntry> rows = new ArrayList<>();

    public PeripheralAccessTableModel(PluginTool tool) {
        super(tool);
    }

    /* ---------- data API (called from controller) ---------- */

    public void setData(List<PeripheralAccessEntry> newRows) {
        rows.clear();
        rows.addAll(newRows);
        fireTableDataChanged();
    }

    /* ---------- GTableModel basics ---------- */

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public List<PeripheralAccessEntry> getModelData() {
        return rows;
    }

    @Override
    public List<PeripheralAccessEntry> getDataSource() {
        return rows;
    }

    @Override
    public String getName() {
        return "Peripheral Accesses";
    }

    /* ---------- column descriptor ---------- */

    @Override
    protected TableColumnDescriptor<PeripheralAccessEntry>
    createTableColumnDescriptor() {

        TableColumnDescriptor<PeripheralAccessEntry> d =
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

    /* ---------- editing support (only “Include” column) ---------- */

    @Override
    public boolean isCellEditable(int row, int col) {
        // editable only when the column’s header is “Include”
        return "Include".equals(getColumnName(col));
    }

    @Override
    public void setValueAt(Object aValue, int row, int col) {
        if ("Include".equals(getColumnName(col))) {
            rows.get(row).setInclude((Boolean) aValue);
            fireTableRowsUpdated(row, row);
        }
    }


    /* ---------- column classes ---------- */

    private abstract static class Column<T>
            extends AbstractDynamicTableColumn<PeripheralAccessEntry, T,
            List<PeripheralAccessEntry>> {

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
            super("Include");
        }

        @Override
        public Boolean getValue(PeripheralAccessEntry r, Settings s,
                                List<PeripheralAccessEntry> d,
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
        public String getValue(PeripheralAccessEntry r, Settings s,
                               List<PeripheralAccessEntry> d,
                               ServiceProvider sp) {
            return r.getMode();
        }
    }

    private static class ConfidenceColumn extends Column<String> {
        ConfidenceColumn() {
            super("Confidence");
        }

        @Override
        public String getValue(PeripheralAccessEntry r, Settings s,
                               List<PeripheralAccessEntry> d,
                               ServiceProvider sp) {
            return r.getConfidence();
        }
    }

    private static class InstrAddrColumn extends Column<Address> {
        InstrAddrColumn() {
            super("Instruction Address");
        }

        @Override
        public Address getValue(PeripheralAccessEntry r, Settings s,
                                List<PeripheralAccessEntry> d,
                                ServiceProvider sp) {
            return r.getInstructionAddress();
        }
    }

    private static class FunctionColumn extends Column<String> {
        FunctionColumn() {
            super("Function");
        }

        @Override
        public String getValue(PeripheralAccessEntry r, Settings s,
                               List<PeripheralAccessEntry> d,
                               ServiceProvider sp) {
            return r.getFunctionName();
        }
    }

    private static class InstructionColumn extends Column<String> {
        InstructionColumn() {
            super("Instruction");
        }

        @Override
        public String getValue(PeripheralAccessEntry r, Settings s,
                               List<PeripheralAccessEntry> d,
                               ServiceProvider sp) {
            return r.getInstructionString();
        }
    }

    private static class PeriphAddrColumn extends Column<Address> {
        PeriphAddrColumn() {
            super("Peripheral Address");
        }

        @Override
        public Address getValue(PeripheralAccessEntry r, Settings s,
                                List<PeripheralAccessEntry> d,
                                ServiceProvider sp) {
            return r.getPeripheralAddress();
        }
    }
}