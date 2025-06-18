package armify.services;

import armify.domain.MMIOAccessEntry;
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

    public List<MMIOAccessEntry> scanMMIOAccesses(Program program, TaskMonitor monitor)
            throws CancelledException {

        List<MMIOAccessEntry> accesses = new ArrayList<>();
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
                if (!AddressUtils.isPeripheralRange(target)) {
                    continue;
                }

                MMIOAccessEntry access = createMMIOAccess(ins, ref, target, program);
                accesses.add(access);
            }
        }

        return accesses;
    }

    private MMIOAccessEntry createMMIOAccess(Instruction ins, Reference ref, Address target, Program program) {
        RefType refType = ref.getReferenceType();
        boolean read = refType.isRead();
        boolean write = refType.isWrite();

        MMIOAccessEntry.AccessMode mode;
        MMIOAccessEntry.ConfidenceLevel confidence;

        if (read && write) {
            mode = MMIOAccessEntry.AccessMode.read_write;
            confidence = MMIOAccessEntry.ConfidenceLevel.high;
        } else if (read) {
            mode = MMIOAccessEntry.AccessMode.read;
            confidence = MMIOAccessEntry.ConfidenceLevel.high;
        } else if (write) {
            mode = MMIOAccessEntry.AccessMode.write;
            confidence = MMIOAccessEntry.ConfidenceLevel.high;
        } else {
            mode = MMIOAccessEntry.AccessMode.unknown;
            confidence = MMIOAccessEntry.ConfidenceLevel.low;
        }

        boolean include = confidence != MMIOAccessEntry.ConfidenceLevel.low;

        Function fn = program.getFunctionManager().getFunctionContaining(ins.getAddress());
        String fnName = (fn != null) ? fn.getName() : "<GLOBAL>";

        return new MMIOAccessEntry(
                include, MMIOAccessEntry.Type.scanned, mode, confidence,
                ins.getAddress(), fnName, ins.toString(), target
        );
    }
}
