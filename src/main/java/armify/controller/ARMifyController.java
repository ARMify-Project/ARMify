package armify.controller;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.CardLayout;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

import armify.model.ARMifyService;
import armify.model.ARMifyService.Record;
import armify.model.PeripheralScanner;
import armify.view.ARMifyComponentProvider;
import armify.view.PeripheralAccessEntry;
import armify.view.PeripheralAccessTableModel;
import docking.widgets.table.GTable;
import docking.widgets.table.GTableFilterPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Orchestrates the background scan and supplies data to the table model.
 */
public class ARMifyController {

    /* analysis helper */
    private final ARMifyService service = new ARMifyService();

    /* provider (window) */
    private final ARMifyComponentProvider provider;

    /* current context */
    private Program program;
    private Record lastRecord;

    /* --- View-A specific members --- */
    private final JPanel viewAPanel = new JPanel();
    private CardLayout cardLayout;
    private PeripheralAccessTableModel tableModel;

    private static final String CARD_LOADING = "loading";
    private static final String CARD_TABLE = "table";

    public ARMifyController(ARMifyComponentProvider provider) {
        this.provider = provider;
    }

    /* ---------------- context update ---------------- */

    public void updateContext(Program program, ProgramLocation location) {
        this.program = program;
        this.lastRecord = service.analyze(program, location);
    }

    /* -------------------- View A -------------------- */

    public JPanel buildMMIOAddressesView() {

        if (program == null) {
            JPanel p = new JPanel(new BorderLayout());
            p.add(new JLabel("No program loaded.",
                    SwingConstants.CENTER), BorderLayout.CENTER);
            return p;
        }

        if (cardLayout == null) {                // first time only
            cardLayout = new CardLayout();
            viewAPanel.setLayout(cardLayout);

            viewAPanel.add(new JLabel("Scanning program…",
                    SwingConstants.CENTER), CARD_LOADING);
            viewAPanel.add(new JPanel(), CARD_TABLE);    // placeholder
        }

        cardLayout.show(viewAPanel, CARD_LOADING);
        startScanTask();                      // async
        return viewAPanel;
    }

    private void startScanTask() {

        PluginTool tool = provider.getTool();

        Task task = new Task("Scanning for peripheral accesses",
                true, true, true) {
            @Override
            public void run(TaskMonitor monitor) throws CancelledException {

                List<PeripheralAccessEntry> rows =
                        PeripheralScanner.scan(program, monitor);

                SwingUtilities.invokeLater(() -> {
                    if (tableModel == null) {
                        tableModel = new PeripheralAccessTableModel(tool);
                    }
                    tableModel.setData(rows);

                    GTable table = new GTable(tableModel);
                    tableModel.installJumpListener(table);
                    table.setAutoResizeMode(GTable.AUTO_RESIZE_ALL_COLUMNS);

                    GTableFilterPanel<PeripheralAccessEntry> filter =
                            new GTableFilterPanel<>(table, tableModel);

                    JPanel tableCard = new JPanel(new BorderLayout());
                    tableCard.add(new JScrollPane(table), BorderLayout.CENTER);
                    tableCard.add(filter, BorderLayout.SOUTH);
                    tableCard.setPreferredSize(new Dimension(800, 400));

                    viewAPanel.add(tableCard, CARD_TABLE);
                    cardLayout.show(viewAPanel, CARD_TABLE);
                });
            }
        };

        tool.execute(task);
    }

    /* -------------------- View B (unchanged) -------------------- */

    public JPanel buildCandidateGroupsView() {
        Record r = lastRecord;
        JPanel p = new JPanel(new java.awt.FlowLayout());
        p.add(new JLabel(r.isInstruction() ? "Instruction: "
                : (r.isDefinedData() ? "Defined Data: "
                : "Undefined Data: ")));
        p.add(new JLabel(r.representation()));
        return p;
    }
}