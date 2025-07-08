package armify.domain;

import armify.services.DatabaseService;
import ghidra.program.model.address.Address;

import java.util.List;

public record RegisterEntry(Address peripheralAddress, int gain, String peripheralName, Address baseAddress,
                            String registerName,
                            List<DatabaseService.FieldInfo> fieldInfos) implements Comparable<RegisterEntry> {

    @Override
    public int compareTo(RegisterEntry registerEntry) {
        return peripheralAddress.compareTo(registerEntry.peripheralAddress());
    }
}