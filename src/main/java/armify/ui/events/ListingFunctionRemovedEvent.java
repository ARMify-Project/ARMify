package armify.ui.events;

import ghidra.program.model.address.Address;

public record ListingFunctionRemovedEvent(Address start, Address end) {
}