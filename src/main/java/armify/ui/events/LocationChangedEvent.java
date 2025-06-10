package armify.ui.events;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

public class LocationChangedEvent {
    private final Program program;
    private final ProgramLocation location;

    public LocationChangedEvent(Program program, ProgramLocation location) {
        this.program = program;
        this.location = location;
    }

    public Program getProgram() {
        return program;
    }

    public ProgramLocation getLocation() {
        return location;
    }
}
