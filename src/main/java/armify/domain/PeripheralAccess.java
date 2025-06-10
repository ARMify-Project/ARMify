package armify.domain;

import ghidra.program.model.address.Address;

public class PeripheralAccess implements Comparable<PeripheralAccess> {
    private boolean include;
    private final AccessMode mode;
    private final ConfidenceLevel confidence;
    private final Address instructionAddress;
    private final String functionName;
    private final String instructionString;
    private final Address peripheralAddress;

    public enum AccessMode {
        read, write, read_write, unknown
    }

    public enum ConfidenceLevel {
        high, medium, low
    }

    public PeripheralAccess(
            boolean include,
            AccessMode mode,
            ConfidenceLevel confidence,
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

    // Getters
    public boolean isInclude() {
        return include;
    }

    public void setInclude(boolean include) {
        this.include = include;
    }

    public AccessMode getMode() {
        return mode;
    }

    public ConfidenceLevel getConfidence() {
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
    public int compareTo(PeripheralAccess other) {
        return instructionAddress.compareTo(other.instructionAddress);
    }
}
