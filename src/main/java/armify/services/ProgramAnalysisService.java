package armify.services;

import armify.domain.PeripheralAccessEntry;
import armify.util.AddressUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

public class ProgramAnalysisService {

    public List<PeripheralAccessEntry> scanPeripheralAccesses(Program program, TaskMonitor monitor)
            throws CancelledException {

        List<PeripheralAccessEntry> accesses = new ArrayList<>();
        Listing listing = program.getListing();
        long totalInsns = listing.getNumInstructions();
        monitor.initialize(totalInsns);

        for (Instruction ins : listing.getInstructions(true)) {
            monitor.checkCancelled();
            monitor.incrementProgress(1);

            for (Reference ref : ins.getReferencesFrom()) {
                if (!ref.isMemoryReference()) {
                    continue;
                }

                Address target = ref.getToAddress();
                if (!AddressUtils.isMmioAddress(target)) {
                    continue;
                }

                PeripheralAccessEntry access = createPeripheralAccess(ins, ref, target, program);
                accesses.add(access);
            }
        }

        return accesses;
    }

    private PeripheralAccessEntry createPeripheralAccess(Instruction ins, Reference ref, Address target, Program program) {
        RefType refType = ref.getReferenceType();
        boolean read = refType.isRead();
        boolean write = refType.isWrite();

        PeripheralAccessEntry.AccessMode mode;
        PeripheralAccessEntry.ConfidenceLevel confidence;

        if (read && write) {
            mode = PeripheralAccessEntry.AccessMode.read_write;
            confidence = PeripheralAccessEntry.ConfidenceLevel.high;
        } else if (read) {
            mode = PeripheralAccessEntry.AccessMode.read;
            confidence = PeripheralAccessEntry.ConfidenceLevel.high;
        } else if (write) {
            mode = PeripheralAccessEntry.AccessMode.write;
            confidence = PeripheralAccessEntry.ConfidenceLevel.high;
        } else {
            mode = PeripheralAccessEntry.AccessMode.unknown;
            confidence = PeripheralAccessEntry.ConfidenceLevel.low;
        }

        boolean include = confidence != PeripheralAccessEntry.ConfidenceLevel.low;

        Function fn = program.getFunctionManager().getFunctionContaining(ins.getAddress());
        String fnName = (fn != null) ? fn.getName() : "<GLOBAL>";

        return new PeripheralAccessEntry(
                include, PeripheralAccessEntry.Type.scanned, mode, confidence,
                ins.getAddress(), fnName, ins.toString(), target
        );
    }
}
