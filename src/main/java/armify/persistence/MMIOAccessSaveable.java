package armify.persistence;

import armify.domain.MMIOAccessEntry;
import armify.domain.MMIOAccessEntry.Type;
import armify.domain.MMIOAccessEntry.AccessMode;
import armify.domain.MMIOAccessEntry.ConfidenceLevel;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

/**
 * Serialisable wrapper around {@link MMIOAccessEntry}.
 */
public class MMIOAccessSaveable implements Saveable {

    /* ---------- persisted fields ---------- */
    private boolean include;
    private byte typeOrdinal;
    private byte modeOrdinal;
    private byte confidenceOrdinal;
    private long registerOffset;
    private long instrOffset;          // −1 = null
    private String functionName;
    private String instructionString;

    private static final long NULL_SENTINEL = -1L;
    private static final int SCHEMA_VER = 1;

    /* required no-arg ctor */
    public MMIOAccessSaveable() {
    }

    public MMIOAccessSaveable(MMIOAccessEntry accessEntry) {
        this.include = accessEntry.isInclude();
        this.typeOrdinal = (byte) accessEntry.getType().ordinal();
        this.modeOrdinal = (byte) accessEntry.getMode().ordinal();
        this.confidenceOrdinal = (byte) accessEntry.getConfidence().ordinal();
        this.registerOffset = accessEntry.getRegisterAddress().getOffset();
        Address ia = accessEntry.getInstructionAddress();
        this.instrOffset = (ia != null) ? ia.getOffset() : NULL_SENTINEL;
        this.functionName = accessEntry.getFunctionName();
        this.instructionString = accessEntry.getInstructionString();
    }

    /* ---------- re-materialise ---------- */
    public MMIOAccessEntry toMMIOAccess(Program program) {

        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Address register = space.getAddress(registerOffset);
        Address instr = (instrOffset == NULL_SENTINEL)
                ? null : space.getAddress(instrOffset);

        return new MMIOAccessEntry(
                include,
                Type.values()[typeOrdinal],
                AccessMode.values()[modeOrdinal],
                ConfidenceLevel.values()[confidenceOrdinal],
                instr,
                functionName,
                instructionString,
                register);
    }

    /* ---------- Saveable impl ---------- */
    @Override
    public void save(ObjectStorage s) {
        s.putBoolean(include);
        s.putByte(typeOrdinal);
        s.putByte(modeOrdinal);
        s.putByte(confidenceOrdinal);
        s.putLong(registerOffset);
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
        registerOffset = s.getLong();
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