package armify.ui.events;

import ghidra.program.model.address.AddressSet;

public record ListingCodePatchedEvent(AddressSet patchedRange) {
}
