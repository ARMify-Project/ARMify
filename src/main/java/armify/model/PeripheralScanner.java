package armify.model;

import java.util.ArrayList;
import java.util.List;

import armify.view.PeripheralAccessEntry;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Pure analysis helper that walks a Program and returns all peripheral
 * accesses it finds.  No Swing/UI code here.
 */
public final class PeripheralScanner {

    private static final long PERIPH_MIN = 0x4000_0000L;
    private static final long PERIPH_MAX = 0x6000_0000L;

    private PeripheralScanner() {
    }

    /**
     * Scan {@code program} and return a fully-populated row list.
     */
    public static List<PeripheralAccessEntry> scan(Program program,
                                                   TaskMonitor monitor) throws CancelledException {

        List<PeripheralAccessEntry> rows = new ArrayList<>();

        Listing listing = program.getListing();
        long insnCnt = listing.getNumInstructions();
        monitor.initialize(insnCnt);

        AddressSpace space = program.getAddressFactory()
                .getDefaultAddressSpace();
        Address min = space.getAddress(PERIPH_MIN);
        Address max = space.getAddress(PERIPH_MAX);

        for (Instruction ins : listing.getInstructions(true)) {
            monitor.checkCanceled();
            monitor.incrementProgress(1);

            for (Reference ref : ins.getReferencesFrom()) {
                if (!ref.isMemoryReference()) {
                    continue;
                }
                Address target = ref.getToAddress();
                if (target == null ||
                        target.compareTo(min) < 0 ||
                        target.compareTo(max) >= 0) {
                    continue;
                }

                /* --------- classify read/write & confidence ---------- */
                RefType refType = ref.getReferenceType();
                String mnemonic = ins.getMnemonicString();
                boolean read = refType.isRead();
                boolean write = refType.isWrite();

                String mode, conf;
                if (read && mnemonic.startsWith("LDR")) {
                    mode = "read";
                    conf = "High";
                } else if (write && mnemonic.startsWith("STR")) {
                    mode = "write";
                    conf = "High";
                } else if (read) {
                    mode = "read";
                    conf = "Medium";
                } else if (write) {
                    mode = "write";
                    conf = "Medium";
                } else {
                    mode = "unknown";
                    conf = "Low";
                }

                boolean include = "write".equals(mode);

                Function fn = program.getFunctionManager()
                        .getFunctionContaining(ins.getAddress());
                String fnName = (fn != null) ? fn.getName() : "<GLOBAL>";

                rows.add(new PeripheralAccessEntry(
                        include, mode, conf,
                        ins.getAddress(),
                        fnName,
                        ins.toString(),
                        target));
            }
        }

        return rows;
    }
}