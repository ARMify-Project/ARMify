package armify.storage;

import java.util.*;

import armify.domain.MMIOAccessEntry;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import ghidra.program.model.listing.Program;
import ghidra.util.Saveable;
import ghidra.util.ObjectStorage;

/**
 * Wraps all MMIOAccessSaveable rows that share the same register address.
 */
public class MMIOAccessListSaveable implements Saveable {
    private static final int SCHEMA_VERSION = 1;
    private static final Gson GSON = new Gson();

    private List<MMIOAccessSaveable> list = new ArrayList<>();

    public MMIOAccessListSaveable() {
    }

    public MMIOAccessListSaveable(Collection<MMIOAccessEntry> rows) {
        for (MMIOAccessEntry e : rows) {
            list.add(new MMIOAccessSaveable(e));
        }
    }

    public List<MMIOAccessEntry> toRows(Program program) {
        List<MMIOAccessEntry> out = new ArrayList<>(list.size());
        for (MMIOAccessSaveable s : list) {
            out.add(s.toMMIOAccess(program));
        }
        return out;
    }

    @Override
    public Class<?>[] getObjectStorageFields() {
        return new Class<?>[]{String.class};
    }

    @Override
    public int getSchemaVersion() {
        return SCHEMA_VERSION;
    }

    @Override
    public void save(ObjectStorage os) {
        os.putString(GSON.toJson(list));
    }

    @Override
    public void restore(ObjectStorage os) {
        String json = os.getString();
        TypeToken<List<MMIOAccessSaveable>> tt = new TypeToken<>() {
        };
        list = GSON.fromJson(json, tt.getType());
    }

    @Override
    public boolean isUpgradeable(int oldSchemaVersion) {
        return false;
    }

    @Override
    public boolean upgrade(ObjectStorage oldStorage,
                           int oldSchemaVersion,
                           ObjectStorage newStorage) {
        return false;
    }

    @Override
    public boolean isPrivate() {
        return false;
    }
}
