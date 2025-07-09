package armify.util;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.task.TaskMonitor;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;

public class ProgramMemory {
    public static void createPeripheralBlock(Program program)
            throws MemoryConflictException, LockException, AddressOverflowException {

        ghidra.program.model.mem.Memory mem = program.getMemory();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Address start = space.getAddress(0x4000_0000L);
        long size = 0x5FFF_FFFFL - 0x4000_0000L + 1;

        MemoryBlock pb = mem.createUninitializedBlock(
                "peripherals", start, size, false);

        // set RW, no-execute
        pb.setPermissions(true, true, false);
    }

    public static void removePeripheralBlock(Program program) throws LockException {
        Memory mem = program.getMemory();
        for (MemoryBlock blk : mem.getBlocks()) {
            if (!blk.getSourceName().equalsIgnoreCase("peripherals")) {
                mem.removeBlock(blk, TaskMonitor.DUMMY);
            }
        }
    }

    public static ArrayList<Long> getSPAndResetVector(Program program) throws MemoryAccessException {
        ArrayList<Long> results = new ArrayList<>();
        Address vectorBase = program.getMinAddress();
        Memory mem = program.getMemory();

        byte[] hdr = new byte[8];
        mem.getBytes(vectorBase, hdr);

        ByteBuffer bb = ByteBuffer.wrap(hdr).order(ByteOrder.LITTLE_ENDIAN);
        results.add(Integer.toUnsignedLong(bb.getInt(0)));
        results.add(Integer.toUnsignedLong(bb.getInt(4)));

        return results;
    }

    public static void removeUserBlocks(Program program) throws LockException {
        Memory mem = program.getMemory();
        for (MemoryBlock blk : mem.getBlocks()) {
            if (!blk.getSourceName().equalsIgnoreCase("Elf Loader") &&
                    !blk.getSourceName().equalsIgnoreCase("Binary Loader")) {
                mem.removeBlock(blk, TaskMonitor.DUMMY);
            }
        }
    }
}
