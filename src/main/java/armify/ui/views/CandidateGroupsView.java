package armify.ui.views;

import armify.domain.EventBus;
import armify.domain.MMIOAccessEntry;
import armify.domain.RegisterEntry;
import armify.services.MatchingEngine;
import armify.ui.components.RegisterTable;
import armify.ui.events.FilterRegisterAddressEvent;
import armify.ui.events.MMIOAccessTableChangedEvent;
import armify.ui.events.RegisterAddressExcludeEvent;
import armify.ui.events.ViewSelectionEvent;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import resources.Icons;
import resources.ResourceManager;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.List;
import java.util.*;
import java.util.stream.Collectors;

public class CandidateGroupsView implements ViewComponent {
    private final MatchingEngine matchingEngine;
    private final EventBus eventBus;

    private final JPanel mainPanel;
    private final RegisterTable registerTable;
    private final JTable groupTable;
    private final JList<String> deviceList;
    private final GroupTableModel groupTableModel;
    private final JButton compareBtn;
    private final JScrollPane groupsScroll;
    private final JScrollPane devicesScroll;
    private final JLabel groupsEmptyLabel =
            new JLabel(" No candidate groups ", SwingConstants.CENTER);
    private final JLabel devicesEmptyLabel =
            new JLabel(" Select exactly one group to view its devices ", SwingConstants.CENTER);

    private List<Address> currentAddress = List.of();
    private List<RegisterEntry> baseRows = List.of();
    private List<RegisterEntry> gainRows = List.of();
    private int tolerance = 0;
    private final List<DockingAction> actions = new ArrayList<>();
    private final PluginTool tool;

    private static final Icon SHOW_ICON = ResourceManager.loadImage("images/table_go.png");

    public CandidateGroupsView(MatchingEngine matchingEngine, EventBus eventBus, PluginTool tool) {
        this.matchingEngine = matchingEngine;
        this.eventBus = eventBus;
        this.tool = tool;

        registerTable = new RegisterTable(tool);
        groupTableModel = new GroupTableModel();
        groupTable = buildGroupsTable();
        deviceList = new JList<>();
        compareBtn = new JButton("Compare…");
        groupsScroll = new JScrollPane(groupTable);
        devicesScroll = new JScrollPane(deviceList);

        mainPanel = new JPanel(new BorderLayout());
        buildUI();
        wireEvents();
        buildActions();
    }

    private void buildUI() {
        // top (MMIO address list)
        JPanel top = new JPanel(new BorderLayout());
        Border tBorder = BorderFactory.createTitledBorder("Included Register Addresses");
        top.setBorder(BorderFactory.createCompoundBorder(tBorder, BorderFactory.createEmptyBorder(5, 0, 0, 0)));
        top.add(registerTable, BorderLayout.CENTER);

        // bottom (groups table | devices list)

        groupsScroll.setBorder(BorderFactory.createTitledBorder("Candidate Groups"));
        devicesScroll.setBorder(BorderFactory.createTitledBorder("Devices in Selected Group"));

        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, groupsScroll, devicesScroll);
        bottomSplit.setResizeWeight(0.65);

        JPanel bottom = new JPanel(new BorderLayout());
        bottom.add(bottomSplit, BorderLayout.CENTER);
        bottom.add(controlPanel(), BorderLayout.SOUTH);

        // vertical split
        //noinspection SuspiciousNameCombination
        JSplitPane vertical = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, bottom);
        vertical.setResizeWeight(0.4);

        mainPanel.add(vertical, BorderLayout.CENTER);
    }

    private JTable buildGroupsTable() {
        JTable t = new JTable(groupTableModel);
        t.setRowHeight(22);
        t.setFillsViewportHeight(true);
        t.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        // selection listener: update detail panes / buttons
        t.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            updateSelectionDependentUI();
        });
        return t;
    }

    private JPanel controlPanel() {

        // root panel with two sides
        JPanel panel = new JPanel(new BorderLayout());

        // left side
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));

        JButton applyBtn = new JButton("Apply");
        JButton resetBtn = new JButton("Reset");
        compareBtn.setEnabled(false);              // still starts disabled

        left.add(applyBtn);
        left.add(resetBtn);
        left.add(compareBtn);

        // right side
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));

        right.add(new JLabel("Tolerance (k):"));

        SpinnerNumberModel kModel = new SpinnerNumberModel(tolerance, 0, 50, 1);
        JSpinner kSpin = new JSpinner(kModel);
        ((JSpinner.NumberEditor) kSpin.getEditor()).getTextField().setColumns(3);
        right.add(kSpin);

        // react to user edits
        kSpin.addChangeListener(e -> {
            tolerance = (int) kSpin.getValue();
            runMatching();
        });

        panel.add(left, BorderLayout.WEST);    // buttons flush-left
        panel.add(right, BorderLayout.EAST);    // label+spinner flush-right
        return panel;
    }

    private void buildActions() {
        actions.add(excludeDockingAction());
        actions.add(showDockingAction());
        actions.add(viewDockingAction());
    }

    private DockingAction excludeDockingAction() {
        DockingAction exclude = new DockingAction("Exclude", "ARMify Plugin") {
            @Override
            public void actionPerformed(ActionContext actionContext) {
                RegisterEntry sel = registerTable.getSelectedEntry();
                if (sel == null) {
                    return;
                }

                int choice = OptionDialog.showYesNoDialog(
                        tool.getActiveWindow(),
                        "Exclude selected register Address",
                        "Should the register address " + sel.peripheralAddress().toString() + " be excluded?");

                if (choice != OptionDialog.YES_OPTION) {
                    return;
                }

                eventBus.publish(new RegisterAddressExcludeEvent(sel.peripheralAddress()));
            }

            @Override
            public boolean isEnabledForContext(ActionContext c) {
                return registerTable.getTable().getSelectedRowCount() == 1;
            }
        };
        exclude.setToolBarData(new ToolBarData(Icons.NOT_ALLOWED_ICON, "0ARMify"));
        exclude.setDescription("Exclude selected register address");
        return exclude;
    }

    private DockingAction showDockingAction() {
        DockingAction show = new DockingAction("Show", "ARMify Plugin") {
            @Override
            public void actionPerformed(ActionContext actionContext) {
                RegisterEntry sel = registerTable.getSelectedEntry();
                if (sel == null) {
                    return;
                }
                Address addr = sel.peripheralAddress();

                // tell the MMIOAccessesView to filter for the address
                eventBus.publish(new FilterRegisterAddressEvent(addr));

                // switch to the MMIOAccessesView
                eventBus.publish(new ViewSelectionEvent(ViewType.MMIO_ACCESSES));
            }

            @Override
            public boolean isEnabledForContext(ActionContext c) {
                return registerTable.getTable().getSelectedRowCount() == 1;
            }
        };
        show.setToolBarData(new ToolBarData(SHOW_ICON, "0ARMify"));
        show.setDescription("Show selected register address in MMIO Accesses");
        return show;
    }

    private DockingAction viewDockingAction() {
        DockingAction view = new DockingAction("View", "ARMify Plugin") {
            @Override
            public void actionPerformed(ActionContext actionContext) {

            }

            @Override
            public boolean isEnabledForContext(ActionContext c) {
                RegisterEntry sel = registerTable.getSelectedEntry();
                return sel != null && sel.baseAddress() != null && registerTable.getTable().getSelectedRowCount() == 1;
            }
        };
        view.setToolBarData(new ToolBarData(Icons.MAKE_SELECTION_ICON, "0ARMify"));
        view.setDescription("View Fields Information");
        return view;
    }

    private void wireEvents() {
        eventBus.subscribe(MMIOAccessTableChangedEvent.class, this::onMMIOTableChanged);
    }

    private void onMMIOTableChanged(MMIOAccessTableChangedEvent ev) {
        Set<Address> uniq = new HashSet<>();
        List<RegisterEntry> regRows = new ArrayList<>();
        for (MMIOAccessEntry m : ev.entries()) {
            if (m.isInclude() && uniq.add(m.getRegisterAddress())) {
                regRows.add(new RegisterEntry(m.getRegisterAddress(), 0, null, null, null));
            }
        }

        baseRows = regRows;
        registerTable.setData(baseRows);
        currentAddress = baseRows.stream()
                .map(RegisterEntry::peripheralAddress)
                .toList();

        runMatching();
    }

    private void runMatching() {
        matchingEngine.recompute(currentAddress, tolerance);

        // reload baseRows with fresh gain values
        gainRows = new ArrayList<>(baseRows.size());
        for (RegisterEntry r : baseRows) {
            int gain = matchingEngine.getGain(r.peripheralAddress());
            gainRows.add(new RegisterEntry(r.peripheralAddress(), gain,
                    r.peripheralName(), r.baseAddress(), r.registerName()));
        }
        registerTable.setData(gainRows);

        var newRows = matchingEngine.getGroups().stream()
                .map(g -> new GroupRow(g.matches(), g.total(), g.deviceNames()))
                .toList();

        groupTableModel.setRows(newRows);

        if (newRows.isEmpty()) {
            groupsScroll.setViewportView(groupsEmptyLabel);
        } else {
            groupsScroll.setViewportView(groupTable);
        }

        deviceList.setListData(new String[0]);          // clear
        devicesScroll.setViewportView(devicesEmptyLabel);
        updateSelectionDependentUI();                   // refresh buttons / placeholders
    }

    private void updateSelectionDependentUI() {
        int[] sel = groupTable.getSelectedRows();

        if (sel.length == 1) {                     // exactly one → show devices + enrich table
            int gIdx = sel[0];

            /* --- update right-hand device list --- */
            GroupRow row = groupTableModel.rows.get(gIdx);
            deviceList.setListData(row.devices().toArray(String[]::new));
            devicesScroll.setViewportView(deviceList);
            compareBtn.setEnabled(false);

            /* --- enrich register rows with names / bases --- */
            List<RegisterEntry> enriched = new ArrayList<>(currentAddress.size());
            for (Address a : currentAddress) {
                var infoOpt = matchingEngine.getRegisterInfo(gIdx, a);
                int gain = matchingEngine.getGain(a);

                if (infoOpt.isPresent()) {
                    var info = infoOpt.get();
                    Address baseAddr =
                            a.getAddressSpace().getAddress(Integer.toUnsignedLong(info.baseAddr()));
                    enriched.add(new RegisterEntry(a, gain,
                            info.peripheral(),
                            baseAddr,
                            info.register()));
                } else {
                    // fall back to address only
                    enriched.add(new RegisterEntry(a, gain, null, null, null));
                }
            }
            registerTable.setData(enriched);
        } else {
            registerTable.setData(gainRows);
            devicesScroll.setViewportView(devicesEmptyLabel);
            compareBtn.setEnabled(sel.length == 2);
        }
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
        registerTable.getTable().getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                tool.contextChanged(provider);
            }
        });

        groupTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateSelectionDependentUI();
                tool.contextChanged(provider);
            }
        });
    }

    private record GroupRow(int matches, int total, List<String> devices) {
        String matchText() {
            return matches + "/" + total;
        }

        String preview() {
            return devices.stream().limit(3).collect(Collectors.joining(", "))
                    + (devices.size() > 3 ? ", …" : "");
        }
    }

    private static class GroupTableModel extends AbstractTableModel {
        enum Col {MATCH, COUNT, PREVIEW}

        private static final String[] NAMES = {"Matches", "Devices", "Preview"};
        private static final Class<?>[] TYPES = {String.class, Integer.class, String.class};

        private final List<GroupRow> rows = new ArrayList<>();

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
        public Object getValueAt(int r, int c) {
            GroupRow row = rows.get(r);
            return switch (Col.values()[c]) {
                case MATCH -> row.matchText();
                case COUNT -> row.devices().size();
                case PREVIEW -> row.preview();
            };
        }

        void setRows(List<GroupRow> list) {
            rows.clear();
            rows.addAll(list);
            fireTableDataChanged();
        }
    }
}
