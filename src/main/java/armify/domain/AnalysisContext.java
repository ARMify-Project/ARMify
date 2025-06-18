package armify.domain;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

import java.util.List;

public class AnalysisContext {
    private final Program program;
    private final ProgramLocation location;
    private final List<MMIOAccessEntry> mmioAccessEntries;
    private final int tolerance;

    public AnalysisContext(
            Program program, ProgramLocation location, List<MMIOAccessEntry> mmioAccessEntries, int tolerance
    ) {
        this.program = program;
        this.location = location;
        this.mmioAccessEntries = List.copyOf(mmioAccessEntries);
        this.tolerance = tolerance;
    }

    public Program getProgram() {
        return program;
    }

    public ProgramLocation getLocation() {
        return location;
    }

    public List<MMIOAccessEntry> getMMIOAccesses() {
        return mmioAccessEntries;
    }

    public int getTolerance() {
        return tolerance;
    }
}
