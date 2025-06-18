package armify.util;

import ghidra.program.model.address.Address;

public class AddressUtils {

    /**
     * Return true if addr falls in the Cortex-M MMIO window:
     * 0x4000_0000-0x5FFF_FFFF – vendor peripheral space
     */
    public static boolean isPeripheralRange(Address addr) {
        if (addr == null) {
            return false;
        }
        long offset = addr.getOffset();
        return offset >= 0x4000_0000L && offset <= 0x5FFF_FFFFL;
    }
}
