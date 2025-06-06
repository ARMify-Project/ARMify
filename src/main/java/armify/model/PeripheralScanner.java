package armify.model;

import java.util.ArrayList;
import java.util.List;

import armify.view.PeripheralAccessEntry;
import ghidra.program.model.address.Address;
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
    // -----------------------------------------------------------------------------
// Scan the whole program and collect every instruction that touches
// a Cortex-M MMIO or core-peripheral address.
// -----------------------------------------------------------------------------
    public static List<PeripheralAccessEntry> scan(Program program,
                                                   TaskMonitor monitor)
            throws CancelledException {

        List<PeripheralAccessEntry> rows = new ArrayList<>();

        Listing listing = program.getListing();
        long totalInsns = listing.getNumInstructions();
        monitor.initialize(totalInsns);

        for (Instruction ins : listing.getInstructions(true)) {
            monitor.checkCancelled();
            monitor.incrementProgress(1);

            // Every reference that the disassembler attached to *this* instruction
            for (Reference ref : ins.getReferencesFrom()) {

                if (!ref.isMemoryReference()) {
                    continue;                       // ignore register/stack/flow refs
                }

                Address target = ref.getToAddress();
                if (!isMmioAddress(target)) {
                    continue;                       // not in an MMIO window – skip
                }

                /* ---------- classify access type & confidence ------------- */
                RefType refType = ref.getReferenceType();
                boolean read = refType.isRead();
                boolean write = refType.isWrite();

                String mode;
                String conf;
                if (read && write) {
                    mode = "Read/Write";            // LDREX, SWP, bit-band RMW…
                    conf = "High";
                } else if (read) {
                    mode = "Read";
                    conf = "High";
                } else if (write) {
                    mode = "Write";
                    conf = "High";
                } else {
                    mode = "Unknown";               // address-taking only
                    conf = "Low";
                }

            /* Include only the solid hits by default; keep the rest for
               potential manual inspection. */
                boolean include = !"Low".equals(conf);

                /* ------------- bookkeeping / row assembly ----------------- */
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

    /* --------------------------------------------------------------------------
     * Return true iff addr falls in the architecturally defined
     * MMIO window on every Cortex-M:
     *   0x4000_0000-0x5FFF_FFFF  – vendor peripheral space (incl. APB/AHB)
     * ------------------------------------------------------------------------- */
    private static boolean isMmioAddress(Address addr) {
        if (addr == null) {
            return false;
        }
        long off = addr.getOffset();

        return off >= 0x4000_0000L && off <= 0x5FFF_FFFFL;
    }
}