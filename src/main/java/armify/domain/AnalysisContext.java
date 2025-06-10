package armify.domain;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

import java.util.List;

public class AnalysisContext {
    private final Program program;
    private final ProgramLocation location;
    private final List<PeripheralAccess> peripheralAccesses;
    private final int tolerance;

    public AnalysisContext(
            Program program, ProgramLocation location, List<PeripheralAccess> peripheralAccesses, int tolerance
    ) {
        this.program = program;
        this.location = location;
        this.peripheralAccesses = List.copyOf(peripheralAccesses);
        this.tolerance = tolerance;
    }

    public Program getProgram() {
        return program;
    }

    public ProgramLocation getLocation() {
        return location;
    }

    public List<PeripheralAccess> getPeripheralAccesses() {
        return peripheralAccesses;
    }

    public int getTolerance() {
        return tolerance;
    }
}
