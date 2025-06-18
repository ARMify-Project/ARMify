package armify.persistence;

import armify.domain.PeripheralAccessEntry;
import armify.domain.PeripheralAccessEntry.Type;
import armify.domain.PeripheralAccessEntry.AccessMode;
import armify.domain.PeripheralAccessEntry.ConfidenceLevel;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

/**
 * Serialisable wrapper around {@link PeripheralAccessEntry}.
 */
public class PeripheralAccessSaveable implements Saveable {

    /* ---------- persisted fields ---------- */
    private boolean include;
    private byte typeOrdinal;
    private byte modeOrdinal;
    private byte confidenceOrdinal;
    private long periphOffset;
    private long instrOffset;          // −1 = null
    private String functionName;
    private String instructionString;

    private static final long NULL_SENTINEL = -1L;
    private static final int SCHEMA_VER = 1;

    /* required no-arg ctor */
    public PeripheralAccessSaveable() {
    }

    public PeripheralAccessSaveable(PeripheralAccessEntry pa) {
        this.include = pa.isInclude();
        this.typeOrdinal = (byte) pa.getType().ordinal();
        this.modeOrdinal = (byte) pa.getMode().ordinal();
        this.confidenceOrdinal = (byte) pa.getConfidence().ordinal();
        this.periphOffset = pa.getPeripheralAddress().getOffset();
        Address ia = pa.getInstructionAddress();
        this.instrOffset = (ia != null) ? ia.getOffset() : NULL_SENTINEL;
        this.functionName = pa.getFunctionName();
        this.instructionString = pa.getInstructionString();
    }

    /* ---------- re-materialise ---------- */
    public PeripheralAccessEntry toPeripheralAccess(Program prog) {

        AddressSpace space = prog.getAddressFactory().getDefaultAddressSpace();
        Address periph = space.getAddress(periphOffset);
        Address instr = (instrOffset == NULL_SENTINEL)
                ? null : space.getAddress(instrOffset);

        return new PeripheralAccessEntry(
                include,
                Type.values()[typeOrdinal],
                AccessMode.values()[modeOrdinal],
                ConfidenceLevel.values()[confidenceOrdinal],
                instr,
                functionName,
                instructionString,
                periph);
    }

    /* ---------- Saveable impl ---------- */
    @Override
    public void save(ObjectStorage s) {
        s.putBoolean(include);
        s.putByte(typeOrdinal);
        s.putByte(modeOrdinal);
        s.putByte(confidenceOrdinal);
        s.putLong(periphOffset);
        s.putLong(instrOffset);
        s.putString(functionName);
        s.putString(instructionString);
    }

    @Override
    public void restore(ObjectStorage s) {
        include = s.getBoolean();
        typeOrdinal = s.getByte();
        modeOrdinal = s.getByte();
        confidenceOrdinal = s.getByte();
        periphOffset = s.getLong();
        instrOffset = s.getLong();
        functionName = s.getString();
        instructionString = s.getString();
    }

    @Override
    public Class<?>[] getObjectStorageFields() {
        return new Class<?>[]{
                boolean.class, byte.class, byte.class, byte.class,
                long.class, long.class, String.class, String.class
        };
    }

    @Override
    public int getSchemaVersion() {
        return SCHEMA_VER;
    }

    @Override
    public boolean isUpgradeable(int v) {
        return false;
    }

    @Override
    public boolean upgrade(ObjectStorage in, int v, ObjectStorage out) {
        return false;
    }

    @Override
    public boolean isPrivate() {
        return false;
    }
}