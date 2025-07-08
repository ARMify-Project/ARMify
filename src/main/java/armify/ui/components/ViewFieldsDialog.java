package armify.ui.components;

import armify.services.DatabaseService;
import docking.DialogComponentProvider;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class ViewFieldsDialog extends DialogComponentProvider {
    private final FieldTable fieldTable;

    public ViewFieldsDialog(String registerName, List<DatabaseService.FieldInfo> fields) {
        super("View Fields for Register: " + registerName, false, true, true, false);

        fieldTable = new FieldTable();

        addWorkPanel(buildMainPanel());
        addDismissButton();

        List<FieldRow> fieldRows = new ArrayList<>();
        for (DatabaseService.FieldInfo field : fields) {
            fieldRows.add(new FieldRow(field.name(), field.msb(), field.lsb()));
        }
        fieldRows.sort(Comparator.comparingInt(FieldRow::lsb));

        fieldTable.setRows(fieldRows);
    }

    private JComponent buildMainPanel() {
        JPanel panel = new JPanel();

        JTable table = new JTable(fieldTable);
        table.setRowHeight(22);
        table.setFillsViewportHeight(true);

        JScrollPane fieldScroll = new JScrollPane(table);
        panel.add(fieldScroll);

        return panel;
    }

    private record FieldRow(String name, int msb, int lsb) {

    }

    private static class FieldTable extends AbstractTableModel {
        enum Col {NAME, MSB, LSB}

        private static final String[] NAMES = {"Name", "MSB", "LSB"};
        private static final Class<?>[] TYPES = {String.class, Integer.class, String.class};

        private final List<FieldRow> rows = new ArrayList<>();

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return NAMES.length;
        }

        @Override
        public String getColumnName(int c) {
            return NAMES[c];
        }

        @Override
        public Class<?> getColumnClass(int c) {
            return TYPES[c];
        }

        @Override
        public boolean isCellEditable(int r, int c) {
            return false;
        }

        @Override
        public Object getValueAt(int i, int c) {
            FieldRow row = rows.get(i);

            return switch (Col.values()[c]) {
                case NAME -> row.name;
                case MSB -> row.msb;
                case LSB -> row.lsb;
            };
        }

        void setRows(List<FieldRow> list) {
            rows.clear();
            rows.addAll(list);
            fireTableDataChanged();
        }
    }
}
