package armify.domain;

import ghidra.program.model.address.Address;

public class MMIOAccessEntry implements Comparable<MMIOAccessEntry> {
    private boolean include;
    private final Type type;
    private final AccessMode mode;
    private final ConfidenceLevel confidence;
    private final Address instructionAddress;
    private final String functionName;
    private final String instructionString;
    private final Address registerAddress;

    public enum Type {
        scanned, custom
    }

    public enum AccessMode {
        read, write, read_write, unknown
    }

    public enum ConfidenceLevel {
        high, medium, low
    }

    public MMIOAccessEntry(
            boolean include,
            Type type,
            AccessMode mode,
            ConfidenceLevel confidence,
            Address instructionAddress,
            String functionName,
            String instructionString,
            Address registerAddress) {
        this.include = include;
        this.type = type;
        this.mode = mode;
        this.confidence = confidence;
        this.instructionAddress = instructionAddress;
        this.functionName = functionName;
        this.instructionString = instructionString;
        this.registerAddress = registerAddress;
    }

    public boolean isInclude() {
        return include;
    }

    public void setInclude(boolean include) {
        this.include = include;
    }

    public Type getType() {
        return type;
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

    public Address getRegisterAddress() {
        return registerAddress;
    }

    @Override
    public int compareTo(MMIOAccessEntry other) {
        return registerAddress.compareTo(other.registerAddress);
    }
}
