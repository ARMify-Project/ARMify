package armify.domain;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

import java.util.List;

public class AnalysisContext {
    private final Program program;
    private final ProgramLocation location;
    private final List<PeripheralAccessEntry> peripheralAccessEntries;
    private final int tolerance;

    public AnalysisContext(
            Program program, ProgramLocation location, List<PeripheralAccessEntry> peripheralAccessEntries, int tolerance
    ) {
        this.program = program;
        this.location = location;
        this.peripheralAccessEntries = List.copyOf(peripheralAccessEntries);
        this.tolerance = tolerance;
    }

    public Program getProgram() {
        return program;
    }

    public ProgramLocation getLocation() {
        return location;
    }

    public List<PeripheralAccessEntry> getPeripheralAccesses() {
        return peripheralAccessEntries;
    }

    public int getTolerance() {
        return tolerance;
    }
}
