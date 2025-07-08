package armify.ui.components;

import armify.services.MatchingEngine;
import docking.DialogComponentProvider;
import docking.widgets.table.GTable;
import ghidra.program.model.address.Address;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class CompareGroupsDialog extends DialogComponentProvider {

    private final DiffTableModel tableModel = new DiffTableModel();
    private final JTextArea detailArea = new JTextArea(5, 80);

    public CompareGroupsDialog(MatchingEngine eng, int aIdx, int bIdx, List<Address> addresses) {

        super("Compare Groups " + aIdx + " ↔ " + bIdx, false, true, true, false);

        buildUi();
        tableModel.setRows(computeDiff(eng, aIdx, bIdx, addresses));
    }

    private void buildUi() {
        GTable tbl = new GTable(tableModel);
        tbl.setRowHeight(22);
        tbl.getSelectionModel().addListSelectionListener(ev -> updateDetails(tbl.getSelectedRow()));

        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(tbl),
                new JScrollPane(detailArea));
        split.setResizeWeight(0.7);
        addWorkPanel(split);
        addDismissButton();
    }

    private void updateDetails(int row) {
        if (row == -1) {
            detailArea.setText("");
            return;
        }
        DiffRow d = tableModel.row(row);
        StringBuilder sb = new StringBuilder();
        d.onlyA.forEach(f -> sb.append("- only in A: ").append(f).append('\n'));
        d.onlyB.forEach(f -> sb.append("+ only in B: ").append(f).append('\n'));
        detailArea.setText(sb.toString());
    }

    private static List<DiffRow> computeDiff(MatchingEngine eng,
                                             int aIdx,
                                             int bIdx,
                                             List<Address> addrs) {

        List<DiffRow> out = new ArrayList<>(addrs.size());
        for (Address a : addrs) {
            var ma = eng.mappingForGroup(aIdx, a).orElse(null);
            var mb = eng.mappingForGroup(bIdx, a).orElse(null);
            if (ma == null || mb == null) {
                continue;                         // group index out of range
            }
            if (Objects.equals(ma.name(), mb.name()) && ma.sigId() == mb.sigId()) {
                continue;                         // identical -> skip
            }

            String reason = switch (ma.state()) {
                case MISSING -> "missing in A";
                case AMBIGUOUS -> "ambiguous in A";
                case OK -> switch (mb.state()) {
                    case MISSING -> "missing in B";
                    case AMBIGUOUS -> "ambiguous in B";
                    default -> ma.name().equals(mb.name()) ? "layout differs"
                            : "name differs";
                };
            };

            List<String> onlyA = List.of();
            List<String> onlyB = List.of();
            if ("layout differs".equals(reason) && ma.sigId() != 0 && mb.sigId() != 0) {
                var fa = eng.regFields(ma.sigId());
                var fb = eng.regFields(mb.sigId());
                onlyA = fa.stream().filter(f -> !fb.contains(f)).map(Object::toString).toList();
                onlyB = fb.stream().filter(f -> !fa.contains(f)).map(Object::toString).toList();
            }

            out.add(new DiffRow(a, ma.name(), mb.name(), reason, onlyA, onlyB));
            if (out.size() == 500) break;         // safety cap
        }
        return out;
    }

    private record DiffRow(Address addr, String nameA, String nameB, String reason, List<String> onlyA,
                           List<String> onlyB) {
    }

    private static class DiffTableModel extends AbstractTableModel {
        private static final String[] N = {"Address", "Group-A", "Group-B", "Reason"};
        private final List<DiffRow> rows = new ArrayList<>();

        DiffRow row(int r) {
            return rows.get(r);
        }

        void setRows(List<DiffRow> r) {
            rows.clear();
            rows.addAll(r);
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return N.length;
        }

        @Override
        public String getColumnName(int c) {
            return N[c];
        }

        @Override
        public Object getValueAt(int r, int c) {
            DiffRow d = rows.get(r);
            return switch (c) {
                case 0 -> d.addr;
                case 1 -> d.nameA;
                case 2 -> d.nameB;
                default -> d.reason;
            };
        }
    }
}
