package armify.controller;

import javax.swing.*;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import armify.model.ARMifyService;
import armify.model.ARMifyService.Record;

import java.awt.*;

public class ARMifyController {
    private final ARMifyService service = new ARMifyService();
    private Program program;
    private ProgramLocation location;
    private Record lastRecord;

    public void updateContext(Program program, ProgramLocation location) {
        this.program = program;
        this.location = location;
        this.lastRecord = service.analyze(program, location);
    }

    public Record getRecord() {
        return lastRecord;
    }

    public JPanel buildViewA() {
        Record r = lastRecord;
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JLabel("Address: " + r.address), BorderLayout.NORTH);
        JTextArea ta = new JTextArea(r.representation);
        ta.setEditable(false);
        p.add(new JScrollPane(ta), BorderLayout.CENTER);
        return p;
    }

    public JPanel buildViewB() {
        Record r = lastRecord;
        JPanel p = new JPanel(new FlowLayout());
        p.add(new JLabel(
                r.isInstruction ? "Instruction: " : (r.isDefinedData ? "Defined Data: " : "Undefined Data: ")
        ));
        p.add(new JLabel(r.representation));
        return p;
    }
}
