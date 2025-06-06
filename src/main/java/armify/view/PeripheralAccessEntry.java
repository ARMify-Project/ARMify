package armify.view;

import ghidra.program.model.address.Address;

/**
 * Data holder for a single peripheral-access entry.
 */
public class PeripheralAccessEntry implements Comparable<PeripheralAccessEntry> {
    // Should this access be included in further analysis?
    private boolean include;

    // "read", "write" or "unknown"
    private String mode;

    // Confidence level: "High", "Medium" or "Low"
    private String confidence;

    // Address of the instruction performing the access
    private Address instructionAddress;

    // Name of the function containing the instruction (or "<GLOBAL>")
    private String functionName;

    // Textual representation of the instruction (e.g., "LDR R0, [R7,#0x10]")
    private String instructionString;

    // The peripheral address being read or written
    private Address peripheralAddress;

    public PeripheralAccessEntry(
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
    public int compareTo(PeripheralAccessEntry peripheralAccessEntry) {
        return instructionAddress.compareTo(peripheralAccessEntry.instructionAddress);
    }
}