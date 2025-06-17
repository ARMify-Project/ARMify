package armify.services;

import armify.domain.PeripheralAccess;
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

    public List<PeripheralAccess> scanPeripheralAccesses(Program program, TaskMonitor monitor)
            throws CancelledException {

        List<PeripheralAccess> accesses = new ArrayList<>();
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

                PeripheralAccess access = createPeripheralAccess(ins, ref, target, program);
                accesses.add(access);
            }
        }

        return accesses;
    }

    private PeripheralAccess createPeripheralAccess(Instruction ins, Reference ref, Address target, Program program) {
        RefType refType = ref.getReferenceType();
        boolean read = refType.isRead();
        boolean write = refType.isWrite();

        PeripheralAccess.AccessMode mode;
        PeripheralAccess.ConfidenceLevel confidence;

        if (read && write) {
            mode = PeripheralAccess.AccessMode.read_write;
            confidence = PeripheralAccess.ConfidenceLevel.high;
        } else if (read) {
            mode = PeripheralAccess.AccessMode.read;
            confidence = PeripheralAccess.ConfidenceLevel.high;
        } else if (write) {
            mode = PeripheralAccess.AccessMode.write;
            confidence = PeripheralAccess.ConfidenceLevel.high;
        } else {
            mode = PeripheralAccess.AccessMode.unknown;
            confidence = PeripheralAccess.ConfidenceLevel.low;
        }

        boolean include = confidence != PeripheralAccess.ConfidenceLevel.low;

        Function fn = program.getFunctionManager().getFunctionContaining(ins.getAddress());
        String fnName = (fn != null) ? fn.getName() : "<GLOBAL>";

        return new PeripheralAccess(
                include, PeripheralAccess.Type.scanned, mode, confidence,
                ins.getAddress(), fnName, ins.toString(), target
        );
    }
}
