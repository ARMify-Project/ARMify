package armify.services;


import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.util.List;

import static armify.util.ProgramMemory.*;

public class DeviceApplyService {
    private final ProgramStorageService storage;
    private final DatabaseService db;

    public DeviceApplyService(ProgramStorageService storage, DatabaseService db) {
        this.storage = storage;
        this.db = db;
    }

    public boolean isApplied(Program program) {
        return (getAppliedDeviceName(program) != null);
    }

    public String getAppliedDeviceName(Program program) {
        return storage.getAppliedDeviceName(program);
    }

    public void apply(Program program, String deviceName) {
        if (program == null || deviceName == null || deviceName.isBlank()) {
            return;
        }

        if (isApplied(program)) {
            reset(program);
        }

        int tx = program.startTransaction("Apply device " + deviceName);
        boolean commit = false;
        try {
            SymbolTable symbolTable = program.getSymbolTable();
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            ProgramBasedDataTypeManager dataTypeManager = program.getDataTypeManager();

            Namespace namespace = symbolTable.getNamespace("Peripherals", null);
            if (namespace == null) {
                try {
                    namespace = program.getSymbolTable().createNameSpace(null, "Peripherals", SourceType.ANALYSIS);
                } catch (DuplicateNameException ex) {
                    Msg.error(this, "Can't create namespace peripheral: duplicate name", ex);
                } catch (InvalidInputException ex) {
                    Msg.error(this, "Can't create namespace peripheral: invalid input", ex);
                }
            }

            // 1. remove peripheral block
            try {
                removePeripheralBlock(program);
            } catch (LockException ex) {
                Msg.error(this, "Can't delete peripheral memory block", ex);
                return;
            }

            // 2. add new memory blocks
            List<DatabaseService.PeripheralInfo> peripherals = db.peripherals(deviceName);
            for (DatabaseService.PeripheralInfo peripheral : peripherals) {
                long length = peripheral.endAddr() - peripheral.baseAddr() + 1;
                try {
                    createMemoryBlock(program, peripheral.name(), peripheral.baseAddr(), length, true, true, false, true);
                } catch (AddressOverflowException ex) {
                    Msg.error(this, "Can't create memory block: address overflow", ex);
                } catch (LockException ex) {
                    Msg.error(this, "Can't create memory block: lock exception", ex);
                } catch (MemoryConflictException ex) {
                    Msg.error(this, "Can't create memory block: memory conflict", ex);
                }

                StructureDataType structureDataType = new StructureDataType(peripheral.name(), (int) length);
                for (DatabaseService.RegisterBrief register : peripheral.registers()) {
                    UnsignedIntegerDataType rType = new UnsignedIntegerDataType(); // TODO respect register size (right data type)
                    structureDataType.replaceAtOffset((int) (register.baseAddr() - peripheral.baseAddr()), rType, 4, register.name(), ""); // TODO respect size
                }

                dataTypeManager.addDataType(structureDataType, DataTypeConflictHandler.REPLACE_HANDLER);
                Address addr = space.getAddress(peripheral.baseAddr());
                try {
                    symbolTable.createLabel(addr, peripheral.name(), namespace, SourceType.USER_DEFINED);
                } catch (InvalidInputException ex) {
                    Msg.error(this, "Can't create label", ex);
                }

                try {
                    program.getListing().createData(addr, structureDataType);
                } catch (CodeUnitInsertionException ex) {
                    Msg.error(this, "Can't create data", ex);
                }

                storage.setAppliedDeviceName(program, deviceName);

                commit = true;
            }
        } finally {
            program.endTransaction(tx, commit);
        }
    }

    public void reset(Program program) {
        if (program == null) {
            return;
        }

        int tx = program.startTransaction("ARMify reset");
        boolean commit = false;
        try {
            SymbolTable symTab = program.getSymbolTable();
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

            // 1. Remove every memory block we added (“Generated by ARMify Plugin”)
            try {
                removeMemoryBlockByComment(program, "Generated by ARMify Plugin");
            } catch (LockException ex) {
                Msg.error(this, "Can't delete generated memory block(s)", ex);
                return;
            }

            // 2. Delete symbols and datatypes that belonged to the device
            String deviceName = storage.getAppliedDeviceName(program);  // may be null
            if (deviceName != null) {
                for (DatabaseService.PeripheralInfo p : db.peripherals(deviceName)) {

                    // 2.a structure datatype
                    DataType dt = dtm.getDataType(new CategoryPath("/"), p.name());
                    if (dt != null) {
                        dtm.remove(dt, TaskMonitor.DUMMY);
                    }

                    // 2.b label at the peripheral base address
                    Address addr = space.getAddress(p.baseAddr());
                    Symbol s = symTab.getPrimarySymbol(addr);
                    if (s != null && s.getName().equals(p.name())) {
                        s.delete();
                    }
                }
            }

            // 3. Delete the “Peripherals” namespace (only if empty)
            Namespace peripheralsNs = symTab.getNamespace("Peripherals", null);
            if (peripheralsNs != null) {
                Symbol nsSymbol = peripheralsNs.getSymbol();
                if (nsSymbol != null && nsSymbol.getSymbolType() == SymbolType.NAMESPACE) {
                    try {
                        nsSymbol.delete();
                    } catch (Exception ex) {
                        // delete() fails if anything is still inside the namespace
                        Msg.warn(this, "Peripherals namespace not empty – left in place", ex);
                    }
                }
            }

            //4. Restore the original, empty “Peripheral” memory block
            try {
                createPeripheralBlock(program);
            } catch (AddressOverflowException | LockException | MemoryConflictException ex) {
                Msg.error(this, "Can't recreate default peripheral block", ex);
            }

            // 5. Clear the stored device name
            storage.setAppliedDeviceName(program, null);
            commit = true;
        } finally {
            program.endTransaction(tx, commit);
        }
    }
}
