package armify.services;

import armify.domain.PeripheralAccessEntry;
import armify.persistence.PeripheralAccessSaveable;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.List;

/**
 * Persistence helper – stores full {@link PeripheralAccessEntry} via an
 * {@link ObjectPropertyMap}.
 */
public class ProgramStorageService {

    private static final String OPT_CATEGORY = "ARMify";
    private static final String OPT_INITIALISED = "Initialised";
    private static final String OPT_K_TOLERANCE = "kTolerance";
    private static final String OPT_ACTIVE_GROUP = "activeGroup";

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

    /* ------------------------------------------------------------------ */
    /* MMIO objects                                                       */
    /* ------------------------------------------------------------------ */

    public void saveMMIOAddresses(Program prog, List<PeripheralAccessEntry> list) {

        int tx = prog.startTransaction("ARMify – save MMIO objects");
        boolean commit = false;

        try {
            PropertyMapManager pm = prog.getUsrPropertyManager();
            pm.removePropertyMap(PROP_MMIO_OBJ);     // nuke old data

            ObjectPropertyMap<PeripheralAccessSaveable> map =
                    pm.createObjectPropertyMap(
                            PROP_MMIO_OBJ, PeripheralAccessSaveable.class);

            for (PeripheralAccessEntry pa : list) {
                map.add(pa.getPeripheralAddress(),
                        new PeripheralAccessSaveable(pa));
            }
            commit = true;
        } catch (Exception ex) {
            Msg.error(this, "Failed to save MMIO objects", ex);
        } finally {
            prog.endTransaction(tx, commit);
        }
    }

    @SuppressWarnings("unchecked")
    public List<PeripheralAccessEntry> loadMMIOAddresses(Program prog) {

        List<PeripheralAccessEntry> out = new ArrayList<>();

        ObjectPropertyMap<?> raw =
                prog.getUsrPropertyManager().getObjectPropertyMap(PROP_MMIO_OBJ);
        if (raw == null) {
            return out;
        }

        ObjectPropertyMap<PeripheralAccessSaveable> map =
                (ObjectPropertyMap<PeripheralAccessSaveable>) raw;

        AddressIterator it = map.getPropertyIterator();
        while (it.hasNext()) {
            Address addr = it.next();
            out.add(map.get(addr).toPeripheralAccess(prog));
        }
        return out;
    }
}