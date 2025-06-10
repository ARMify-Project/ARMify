package armify.view;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.GDynamicColumnTableModel;
import docking.widgets.table.RowObjectTableModel;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.services.GoToService;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

import javax.swing.*;

/**
 * Lightweight table-model: holds pre-computed rows supplied by the
 * controller.  No program-scanning logic lives here.
 */
public class MMIOAddressTableModel
        extends GDynamicColumnTableModel<MMIOAddressTableEntry,
        List<MMIOAddressTableEntry>> {

    private final List<MMIOAddressTableEntry> rows = new ArrayList<>();
    private final PluginTool tool;

    public MMIOAddressTableModel(PluginTool tool) {
        super(tool);
        this.tool = tool;
    }

    /* ---------- data API (called from controller) ---------- */

    public void setData(List<MMIOAddressTableEntry> newRows) {
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
    public List<MMIOAddressTableEntry> getModelData() {
        return rows;
    }

    @Override
    public List<MMIOAddressTableEntry> getDataSource() {
        return rows;
    }

    @Override
    public String getName() {
        return "Peripheral Accesses";
    }

    /* ---------- column descriptor ---------- */

    @Override
    protected TableColumnDescriptor<MMIOAddressTableEntry>
    createTableColumnDescriptor() {

        TableColumnDescriptor<MMIOAddressTableEntry> d =
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
            extends AbstractDynamicTableColumn<MMIOAddressTableEntry, T,
            List<MMIOAddressTableEntry>> {

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
        public Boolean getValue(MMIOAddressTableEntry r, Settings s,
                                List<MMIOAddressTableEntry> d,
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
        public String getValue(MMIOAddressTableEntry r, Settings s,
                               List<MMIOAddressTableEntry> d,
                               ServiceProvider sp) {
            return r.getMode();
        }
    }

    private static class ConfidenceColumn extends Column<String> {
        ConfidenceColumn() {
            super("Confidence");
        }

        @Override
        public String getValue(MMIOAddressTableEntry r, Settings s,
                               List<MMIOAddressTableEntry> d,
                               ServiceProvider sp) {
            return r.getConfidence();
        }
    }

    private static class InstrAddrColumn extends Column<Address> {
        InstrAddrColumn() {
            super("Instruction Address");
        }

        @Override
        public Address getValue(MMIOAddressTableEntry r, Settings s,
                                List<MMIOAddressTableEntry> d,
                                ServiceProvider sp) {
            return r.getInstructionAddress();
        }
    }

    private static class FunctionColumn extends Column<String> {
        FunctionColumn() {
            super("Function");
        }

        @Override
        public String getValue(MMIOAddressTableEntry r, Settings s,
                               List<MMIOAddressTableEntry> d,
                               ServiceProvider sp) {
            return r.getFunctionName();
        }
    }

    private static class InstructionColumn extends Column<String> {
        InstructionColumn() {
            super("Instruction");
        }

        @Override
        public String getValue(MMIOAddressTableEntry r, Settings s,
                               List<MMIOAddressTableEntry> d,
                               ServiceProvider sp) {
            return r.getInstructionString();
        }
    }

    private static class PeriphAddrColumn extends Column<Address> {
        PeriphAddrColumn() {
            super("Peripheral Address");
        }

        @Override
        public Address getValue(MMIOAddressTableEntry r, Settings s,
                                List<MMIOAddressTableEntry> d,
                                ServiceProvider sp) {
            return r.getPeripheralAddress();
        }
    }

    /* ================================================================== */
    /* Left-click navigation                                              */
    /* ================================================================== */

    public void installJumpListener(JTable table) {

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e) || e.getClickCount() != 1) {
                    return;
                }

                int viewRow = table.rowAtPoint(e.getPoint());
                int viewCol = table.columnAtPoint(e.getPoint());
                if (viewRow < 0 || viewCol < 0) {
                    return;
                }

                String colName = table.getColumnName(viewCol);
                if (!Set.of("Instruction Address", "Instruction", "Peripheral Address").contains(colName)) {
                    return;
                }

                // The model the JTable is currently using (after filtering)
                RowObjectTableModel<MMIOAddressTableEntry> model =
                        (RowObjectTableModel<MMIOAddressTableEntry>) table.getModel();

                MMIOAddressTableEntry entry =
                        model.getRowObject(table.convertRowIndexToModel(viewRow));

                Address dest = "Peripheral Address".equals(colName)
                        ? entry.getPeripheralAddress()
                        : entry.getInstructionAddress();

                goTo(dest);
            }
        });
    }

    private void goTo(Address addr) {
        GoToService gotoSvc = tool.getService(GoToService.class);
        if (gotoSvc != null) {
            gotoSvc.goTo(addr);
        } else {
            Msg.showWarn(this, null, "Navigation service missing",
                    "Cannot navigate to " + addr);
        }
    }
}