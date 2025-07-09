package armify.services;

import armify.domain.MMIOAccessEntry;
import armify.storage.MMIOAccessListSaveable;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ProgramStorageService {

    private static final String OPT_CATEGORY = "ARMify";
    private static final String OPT_INITIALISED = "Initialised";
    private static final String OPT_K_TOLERANCE = "kTolerance";
    private static final String OPT_APPLIED_DEVICE_NAME = "AppliedDeviceName";

    private static final String PROP_MMIO_OBJ = "ARMify.MMIO.obj";

    /* ------------------------------------------------------------------ */
    /* Options                                                            */
    /* ------------------------------------------------------------------ */

    public boolean isInitialised(Program p) {
        return p.getOptions(OPT_CATEGORY).getBoolean(OPT_INITIALISED, false);
    }

    public void setInitialised(Program prog, boolean value) {
        int txId = prog.startTransaction("ARMify – set init flag");
        try {
            prog.getOptions(OPT_CATEGORY).setBoolean(OPT_INITIALISED, value);
        } finally {
            prog.endTransaction(txId, true);
        }
    }

    public void setkTolerance(Program prog, int kTolerance) {
        int txId = prog.startTransaction("ARMify – set kTolerance");
        try {
            prog.getOptions(OPT_CATEGORY).setInt(OPT_K_TOLERANCE, kTolerance);
        } finally {
            prog.endTransaction(txId, true);
        }
    }

    public int getkTolerance(Program prog) {
        return prog.getOptions(OPT_CATEGORY).getInt(OPT_K_TOLERANCE, 0);
    }

    public void setAppliedDeviceName(Program prog, String deviceName) {
        int txId = prog.startTransaction("ARMify – set device name");
        try {
            prog.getOptions(OPT_CATEGORY).setString(OPT_APPLIED_DEVICE_NAME, deviceName);
        } finally {
            prog.endTransaction(txId, true);
        }
    }

    public String getAppliedDeviceName(Program prog) {
        return prog.getOptions(OPT_CATEGORY).getString(OPT_APPLIED_DEVICE_NAME, null);
    }

    /* ------------------------------------------------------------------ */
    /* MMIO objects                                                       */
    /* ------------------------------------------------------------------ */

    public void saveMMIOAccesses(Program prog, List<MMIOAccessEntry> list) {
        if (prog == null) {
            return;
        }
        PropertyMapManager pmMgr = prog.getUsrPropertyManager();
        if (pmMgr == null) { // scratch program
            return;
        }

        int tx = prog.startTransaction("ARMify – save MMIO objects");
        boolean commit = false;

        try {
            PropertyMapManager pm = prog.getUsrPropertyManager();
            pm.removePropertyMap(PROP_MMIO_OBJ);     // nuke old data

            ObjectPropertyMap<MMIOAccessListSaveable> map =
                    pm.createObjectPropertyMap(
                            PROP_MMIO_OBJ, MMIOAccessListSaveable.class);

            // group by register address
            Map<Address, List<MMIOAccessEntry>> bucket = new HashMap<>();
            for (MMIOAccessEntry e : list) {
                bucket.computeIfAbsent(e.getRegisterAddress(),
                        k -> new ArrayList<>()).add(e);
            }


            // persist
            for (var g : bucket.entrySet()) {
                map.add(g.getKey(), new MMIOAccessListSaveable(g.getValue()));
            }
            commit = true;
        } catch (Exception ex) {
            Msg.error(this, "Failed to save MMIO objects", ex);
        } finally {
            prog.endTransaction(tx, commit);
        }
    }

    public List<MMIOAccessEntry> loadMMIOAccesses(Program program) {
        if (program == null) {
            return List.of();
        }
        PropertyMapManager pmMgr = program.getUsrPropertyManager();
        if (pmMgr == null) { // scratch program
            return List.of();
        }

        @SuppressWarnings("unchecked")
        ObjectPropertyMap<MMIOAccessListSaveable> map =
                (ObjectPropertyMap<MMIOAccessListSaveable>) pmMgr.getObjectPropertyMap(PROP_MMIO_OBJ);

        if (map == null) {
            return List.of();
        }

        List<MMIOAccessEntry> out = new ArrayList<>();
        for (Address regAddr : map.getPropertyIterator()) {
            out.addAll(map.get(regAddr).toRows(program));
        }
        out.sort(null);
        return out;
    }
}