package armify.ui.components;

import armify.domain.RegisterEntry;
import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class RegisterTable extends JPanel {
    private final RegisterTableModel tableModel;
    private final GTable table;

    public RegisterTable(PluginTool tool) {
        super(new BorderLayout());

        tableModel = new RegisterTableModel(tool);
        table = new GTable(tableModel);

        table.setRowSelectionAllowed(true);
        table.setColumnSelectionAllowed(false);
        table.setAutoResizeMode(GTable.AUTO_RESIZE_ALL_COLUMNS);

        add(new JScrollPane(table), BorderLayout.CENTER);

        GTableFilterPanel<RegisterEntry> filter =
                new GTableFilterPanel<>(table, tableModel);
        add(filter, BorderLayout.SOUTH);
    }

    public void setData(List<RegisterEntry> rows) {
        tableModel.setData(rows);
    }

    public GTable getTable() {
        return table;
    }

    private static class RegisterTableModel
            extends GDynamicColumnTableModel<RegisterEntry, List<RegisterEntry>> {

        private final List<RegisterEntry> rows = new ArrayList<>();

        RegisterTableModel(PluginTool tool) {
            super(tool);
        }

        void setData(List<RegisterEntry> newRows) {
            rows.clear();
            rows.addAll(newRows);
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public List<RegisterEntry> getModelData() {
            return rows;
        }

        @Override
        public List<RegisterEntry> getDataSource() {
            return rows;
        }

        @Override
        public String getName() {
            return "Register Grouped";
        }

        @Override
        protected TableColumnDescriptor<RegisterEntry> createTableColumnDescriptor() {
            TableColumnDescriptor<RegisterEntry> d = new TableColumnDescriptor<>();

            d.addVisibleColumn(new RegisterAddrColumn());
            d.addVisibleColumn(new GainColumn());
            d.addVisibleColumn(new RegisterColumn());
            d.addVisibleColumn(new PeripheralColumn());
            d.addVisibleColumn(new BaseAddrColumn());

            return d;
        }

        @Override
        public boolean isCellEditable(int row, int col) {
            return false;
        }

        private abstract static class Column<T>
                extends AbstractDynamicTableColumn<RegisterEntry, T, List<RegisterEntry>> {
            private final String name;

            Column(String name) {
                this.name = name;
            }

            @Override
            public String getColumnName() {
                return name;
            }
        }

        private static class RegisterAddrColumn extends Column<Address> {
            RegisterAddrColumn() {
                super("Reg. Addr.");
            }

            @Override
            public Address getValue(RegisterEntry r, Settings s,
                                    List<RegisterEntry> d, ServiceProvider sp) {
                return r.peripheralAddress();
            }

            @Override
            public String getColumnDescription() {
                return "Register Address";
            }
        }

        private static class GainColumn extends Column<Integer> {
            GainColumn() {
                super("Gain");
            }

            @Override
            public Integer getValue(RegisterEntry r, Settings s,
                                    List<RegisterEntry> d, ServiceProvider sp) {
                return r.gain();
            }

            @Override
            public String getColumnDescription() {
                return "How many extra devices would qualify if this address were unchecked";
            }
        }

        private static class RegisterColumn extends Column<String> {
            RegisterColumn() {
                super("Register");
            }

            @Override
            public String getValue(RegisterEntry r, Settings s,
                                   List<RegisterEntry> d, ServiceProvider sp) {
                return r.registerName() != null ? r.registerName() : "";
            }

            @Override
            public String getColumnDescription() {
                return "Register Name";
            }
        }

        private static class BaseAddrColumn extends Column<Address> {
            BaseAddrColumn() {
                super("Base Addr.");
            }

            @Override
            public Address getValue(RegisterEntry r, Settings s,
                                    List<RegisterEntry> d, ServiceProvider sp) {
                return r.baseAddress();
            }

            @Override
            public String getColumnDescription() {
                return "Base Address of Peripheral";
            }
        }

        private static class PeripheralColumn extends Column<String> {
            PeripheralColumn() {
                super("Peripheral");
            }

            @Override
            public String getValue(RegisterEntry r, Settings s,
                                   List<RegisterEntry> d, ServiceProvider sp) {
                return r.peripheralName();
            }

            @Override
            public String getColumnDescription() {
                return "Peripheral Name";
            }
        }
    }
}
