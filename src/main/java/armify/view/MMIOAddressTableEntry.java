package armify.view;

import ghidra.program.model.address.Address;

/**
 * Data holder for a single peripheral-access entry.
 */
public class MMIOAddressTableEntry implements Comparable<MMIOAddressTableEntry> {
    // Should this access be included in further analysis?
    private boolean include;

    // "read", "write" or "unknown"
    private final String mode;

    // Confidence level: "High", "Medium" or "Low"
    private final String confidence;

    // Address of the instruction performing the access
    private final Address instructionAddress;

    // Name of the function containing the instruction (or "<GLOBAL>")
    private final String functionName;

    // Textual representation of the instruction (e.g., "LDR R0, [R7,#0x10]")
    private final String instructionString;

    // The peripheral address being read or written
    private final Address peripheralAddress;

    public MMIOAddressTableEntry(
            boolean include,
            String mode,
            String confidence,
            Address instructionAddress,
            String functionName,
            String instructionString,
            Address peripheralAddress) {
        this.include = include;
        this.mode = mode;
        this.confidence = confidence;
        this.instructionAddress = instructionAddress;
        this.functionName = functionName;
        this.instructionString = instructionString;
        this.peripheralAddress = peripheralAddress;
    }

    public boolean isInclude() {
        return include;
    }

    public void setInclude(boolean include) {
        this.include = include;
    }

    public String getMode() {
        return mode;
    }

    public String getConfidence() {
        return confidence;
    }

    public Address getInstructionAddress() {
        return instructionAddress;
    }

    public String getFunctionName() {
        return functionName;
    }

    public String getInstructionString() {
        return instructionString;
    }

    public Address getPeripheralAddress() {
        return peripheralAddress;
    }

    @Override
    public int compareTo(MMIOAddressTableEntry MMIOAddressTableEntry) {
        return instructionAddress.compareTo(MMIOAddressTableEntry.instructionAddress);
    }
}