package armify.ui.events;

import ghidra.program.model.listing.Program;

public record ProgramChangedEvent(Program program) {
}
