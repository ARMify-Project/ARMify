package armify.ui.events;

import ghidra.program.model.address.Address;

public record ListingFunctionAddedEvent(Address start, Address end, String name) {
}