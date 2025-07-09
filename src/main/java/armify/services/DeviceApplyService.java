package armify.services;


import ghidra.program.model.listing.Program;

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
        storage.setAppliedDeviceName(program, deviceName);
    }

    public void reset(Program program) {
        storage.setAppliedDeviceName(program, null);
    }
}
