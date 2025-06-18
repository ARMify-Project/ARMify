package armify.domain;

import ghidra.program.model.address.Address;

public record RegisterEntry(Address peripheralAddress, String peripheralName, Address baseAddress,
                            String registerName) implements Comparable<RegisterEntry> {

    @Override
    public int compareTo(RegisterEntry registerEntry) {
        return peripheralAddress.compareTo(registerEntry.peripheralAddress());
    }
}
