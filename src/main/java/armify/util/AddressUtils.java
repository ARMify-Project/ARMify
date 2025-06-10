package armify.util;

import ghidra.program.model.address.Address;

public class AddressUtils {
    
    /**
     * Return true if addr falls in the Cortex-M MMIO window:
     * 0x4000_0000-0x5FFF_FFFF – vendor peripheral space
     */
    public static boolean isMmioAddress(Address addr) {
        if (addr == null) {
            return false;
        }
        long offset = addr.getOffset();
        return offset >= 0x4000_0000L && offset <= 0x5FFF_FFFFL;
    }

    /**
     * Heuristic to determine if an address is likely a peripheral base
     */
    public static boolean isPeripheralBase(long addr) {
        return (addr & 0xFFF) == 0; // Aligned to 4KB boundary
    }
}
