package armify.ui.events;

import ghidra.program.model.address.Address;

public record FilterRegisterAddressEvent(Address registerAddress) {
}
