package armify.ui.events;

import ghidra.program.model.address.Address;

public record ListingFunctionRenamedEvent(Address start, Address end, String oldName, String newName) {
}
