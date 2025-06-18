package armify.ui.components;

import armify.domain.PeripheralAccessEntry;
import armify.domain.PeripheralAccessEntry.AccessMode;
import armify.domain.PeripheralAccessEntry.ConfidenceLevel;
import docking.DialogComponentProvider;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.AddressInput;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.*;
import java.util.function.Consumer;

public class AddPeripheralAccessDialog extends DialogComponentProvider {
    private final PluginTool tool;
    private final Program program;
    private final Consumer<PeripheralAccessEntry> onAccept;

    private final JCheckBox includeCheck = new JCheckBox();
    private final JComboBox<AccessMode> modeCombo = new JComboBox<>(AccessMode.values());
    private final JComboBox<ConfidenceLevel> confCombo = new JComboBox<>(ConfidenceLevel.values());
    private final AddressInput instrAddrInput = new AddressInput();
    private final AddressInput periphAddrInput = new AddressInput();
    private final JButton instrPickBtn = makePickButton(instrAddrInput);
    private final JButton periphPickBtn = makePickButton(periphAddrInput);

    private static final long PERIPH_MIN = 0x4000_0000L;
    private static final long PERIPH_MAX = 0x5FFF_FFFFL;

    public AddPeripheralAccessDialog(
            PluginTool tool, Program program, PeripheralAccessEntry initialRow, Consumer<PeripheralAccessEntry> onAccept) {
        super((initialRow == null) ? "Add Peripheral Access" : "Edit Peripheral Access",
                false, true, true, false);
        this.tool = tool;
        this.program = program;
        this.onAccept = onAccept;

        instrAddrInput.setProgram(program);
        periphAddrInput.setProgram(program);

        if (initialRow != null) {
            includeCheck.setSelected(initialRow.isInclude());
            modeCombo.setSelectedItem(initialRow.getMode());
            confCombo.setSelectedItem(initialRow.getConfidence());
            if (initialRow.getInstructionAddress() != null) {
                instrAddrInput.setAddress(initialRow.getInstructionAddress());
            }
            periphAddrInput.setAddress(initialRow.getPeripheralAddress());
        } else {
            includeCheck.setSelected(true);
            confCombo.setSelectedItem(ConfidenceLevel.high);
            modeCombo.setSelectedItem(AccessMode.unknown);
        }

        addWorkPanel(buildMainPanel());
        addOKButton();
        addCancelButton();
    }

    @Override
    protected void okCallback() {
        Address instrAddr = null;
        String functionName = "";
        String instrString = "";

        if (!periphAddrInput.hasInput()) {
            setStatusText("Peripheral address is mandatory");
            return;
        }

        Address periphAddress = periphAddrInput.getAddress();
        if (periphAddress == null) {
            setStatusText("Peripheral address is not a valid address");
            return;
        }

        long addrOff = periphAddress.getOffset();
        if (addrOff < PERIPH_MIN || addrOff > PERIPH_MAX) {
            setStatusText("Peripheral address must be in 0x4000_0000 – 0x5FFF_FFFF");
            return;
        }

        if (instrAddrInput.hasInput()) {
            instrAddr = instrAddrInput.getAddress();

            if (instrAddr == null) {
                setStatusText("Instruction address is not a valid address");
                return;
            }

            Instruction ins = program.getListing().getInstructionAt(instrAddr);
            Function fn = program.getFunctionManager().getFunctionContaining(instrAddr);

            if (ins != null) {
                instrString = ins.toString();
            } else {
                setStatusText("Entered instruction address does not contain a valid instruction");
                return;
            }

            if (fn != null) {
                functionName = fn.getName();
            } else {
                functionName = "<GLOBAL>";
            }
        }

        PeripheralAccessEntry pa = new PeripheralAccessEntry(
                includeCheck.isSelected(),
                PeripheralAccessEntry.Type.custom,
                (AccessMode) modeCombo.getSelectedItem(),
                (ConfidenceLevel) confCombo.getSelectedItem(),
                instrAddr,
                functionName,
                instrString,
                periphAddrInput.getAddress());

        onAccept.accept(pa);
        close();
    }

    private JButton makePickButton(AddressInput target) {

        Icon icon = ResourceManager.loadImage("images/pipette.png");
        JButton btn = new JButton(icon);
        btn.setFocusable(false);
        btn.setToolTipText("Fill with cursor address");

        btn.addActionListener(e -> {
            CodeViewerService cvs = tool.getService(CodeViewerService.class);
            ProgramLocation loc = (cvs != null) ? cvs.getCurrentLocation() : null;

            if (loc != null && loc.getProgram() == program) {
                target.setAddress(loc.getAddress());
            } else {
                setStatusText("No cursor location available in this program");
            }
        });
        return btn;
    }

    private JComponent buildMainPanel() {

        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 4, 4, 4);
        g.anchor = GridBagConstraints.WEST;

        int row = 0;

        /* ---------- Include ---------- */
        g.gridx = 0;
        g.gridy = row;
        p.add(new JLabel("Include:"), g);
        g.gridx = 1;
        p.add(includeCheck, g);

        /* ---------- Mode ---------- */
        row++;
        g.gridx = 0;
        g.gridy = row;
        p.add(new JLabel("Mode:"), g);
        g.gridx = 1;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        p.add(modeCombo, g);

        /* ---------- Confidence ---------- */
        row++;
        g.gridx = 0;
        g.gridy = row;
        g.weightx = 0;
        g.fill = GridBagConstraints.NONE;
        p.add(new JLabel("Confidence:"), g);
        g.gridx = 1;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        p.add(confCombo, g);

        /* ---------- Instruction Address + pick ---------- */
        row++;
        g.gridx = 0;
        g.gridy = row;
        g.weightx = 0;
        g.fill = GridBagConstraints.NONE;
        p.add(new JLabel("Instruction Address (Optional):"), g);
        g.gridx = 1;
        g.gridwidth = 2;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        p.add(instrAddrInput, g);
        g.gridx = 3;
        g.gridwidth = 1;
        g.weightx = 0;
        g.fill = GridBagConstraints.NONE;
        p.add(instrPickBtn, g);

        /* ---------- Peripheral Address + pick ---------- */
        row++;
        g.gridx = 0;
        g.gridy = row;
        p.add(new JLabel("Peripheral Address:"), g);
        g.gridx = 1;
        g.gridwidth = 2;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        p.add(periphAddrInput, g);
        g.gridx = 3;
        g.gridwidth = 1;
        g.weightx = 0;
        g.fill = GridBagConstraints.NONE;
        p.add(periphPickBtn, g);

        return p;
    }
}