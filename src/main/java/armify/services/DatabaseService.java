package armify.services;

import ghidra.program.model.address.Address;

import java.nio.file.Path;
import java.sql.*;
import java.util.*;

/**
 * Thin, read-only façade around the canonical SQLite device database.
 * <p>
 * * opens the DB in immutable/WAL mode when possible
 * * small metadata caches
 * * *new* overload that takes {@link Address} to avoid boiler-plate in UI code
 */
public class DatabaseService implements AutoCloseable {

    // ───────────────── constants ──────────────────
    private static final int SQLITE_MAX_VARIABLE_NUMBER = 999;

    // ───────────────── state ───────────────────────
    private final Connection conn;
    private final Map<Integer, String> nameCache = new HashMap<>();

    // ───────────────── ctor ────────────────────────
    public DatabaseService(Path dbPath) {
        try {
            Class.forName("org.sqlite.JDBC");
            String url = "jdbc:sqlite:file:" + dbPath.toAbsolutePath() + "?immutable=1";
            this.conn = DriverManager.getConnection(url);

            try (Statement st = conn.createStatement()) {
                /* change journal mode only when we can write */
                if (!url.contains("immutable=1")) {
                    st.execute("PRAGMA journal_mode=WAL");
                }
                st.execute("PRAGMA mmap_size = 268435456");
            }
        } catch (SQLException | ClassNotFoundException ex) {
            throw new RuntimeException("Cannot open SQLite DB at " + dbPath, ex);
        }
    }

    // ═════════════════ public API ═══════════════════

    /* ------------------------------------------------------------------
     * 1)  original: List<Long>
     * ------------------------------------------------------------------ */
    public Map<Long, List<AddressHit>> queryAddresses(List<Long> addresses) {
        Map<Long, List<AddressHit>> hits = new HashMap<>();
        if (addresses == null || addresses.isEmpty()) {
            return hits;
        }

        /* SQLite allows only 999 bind variables by default – chunk if needed */
        int from = 0, total = addresses.size();
        while (from < total) {
            int to = Math.min(from + SQLITE_MAX_VARIABLE_NUMBER, total);
            queryChunk(addresses.subList(from, to), hits);
            from = to;
        }
        return hits;
    }

    /* ------------------------------------------------------------------
     * 2)  overload: List<Address>  (Ghidra Address)
     * ------------------------------------------------------------------ */
    public Map<Long, List<AddressHit>> queryAddressesFromAddresses(List<Address> ghidraAddresses) {
        if (ghidraAddresses == null || ghidraAddresses.isEmpty()) {
            return Collections.emptyMap();
        }
        List<Long> offsets = new ArrayList<>(ghidraAddresses.size());
        for (Address a : ghidraAddresses) {
            offsets.add(a.getOffset());           // Ghidra  → long
        }
        return queryAddresses(offsets);
    }

    // ═════════════════ helpers ══════════════════════

    /**
     * one chunk ≤ 999 variables
     */
    private void queryChunk(List<Long> addresses, Map<Long, List<AddressHit>> out) {
        String placeholders = String.join(",", Collections.nCopies(addresses.size(), "?"));
        String sql = "SELECT addr, device_id, sig_id FROM addr2dev WHERE addr IN (" + placeholders + ")";

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (int i = 0; i < addresses.size(); i++) {
                ps.setLong(i + 1, addresses.get(i));
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    long addr = rs.getLong("addr");
                    int dev = rs.getInt("device_id");
                    int sig = rs.getInt("sig_id");
                    out.computeIfAbsent(addr, k -> new ArrayList<>())
                            .add(new AddressHit(addr, dev, sig));
                }
            }
        } catch (SQLException ex) {
            throw new RuntimeException("addr2dev query failed", ex);
        }
    }

    /* --- unchanged metadata helpers & cache --------------------------- */

    public String deviceName(int deviceId) {
        return nameCache.computeIfAbsent(deviceId, id -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT name FROM devices WHERE id = ?")) {
                ps.setInt(1, id);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getString(1) : "id:" + id;
                }
            } catch (SQLException ex) {
                throw new RuntimeException("device name query failed", ex);
            }
        });
    }

    public Optional<RegisterInfo> registerInfo(int deviceId, long addr) {
        String sql = """
                SELECT p.name       AS periph,
                       p.base_addr  AS base,
                       r.name       AS reg,
                       r.sig_id     AS sig
                  FROM registers r
                  JOIN peripherals p ON p.id = r.peripheral_id
                 WHERE p.device_id = ? AND r.base_addr = ? LIMIT 1
                """;
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, deviceId);
            ps.setLong(2, addr);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return Optional.empty();
                List<FieldInfo> fields = regFields(rs.getInt("sig"));
                return Optional.of(new RegisterInfo(
                        rs.getString("periph"),
                        rs.getInt("base"),
                        rs.getString("reg"),
                        rs.getInt("sig"),
                        fields
                ));
            }
        } catch (SQLException ex) {
            throw new RuntimeException("register_info query failed", ex);
        }
    }

    public List<FieldInfo> regFields(int sigId) {
        List<FieldInfo> list = new ArrayList<>();
        String sql = """
                  SELECT name, lsb, msb
                    FROM reg_fields
                   WHERE sig_id = ?
                ORDER BY lsb, msb, name
                """;
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, sigId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(new FieldInfo(
                            rs.getString("name"),
                            rs.getInt("lsb"),
                            rs.getInt("msb")));
                }
            }
        } catch (SQLException ex) {
            throw new RuntimeException("reg_fields query failed", ex);
        }
        return list;
    }

    public List<PeripheralInfo> peripherals(String deviceName) {
        if (deviceName == null || deviceName.isBlank()) {
            return Collections.emptyList();
        }

        // 1. resolve the device-id
        Integer deviceId = null;
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id FROM devices WHERE name = ? LIMIT 1")) {
            ps.setString(1, deviceName);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    deviceId = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw new RuntimeException("device id query failed", ex);
        }
        if (deviceId == null) {
            return Collections.emptyList();  // unknown device name
        }

        // 2. fetch peripherals for that device (sorted)
        List<PeripheralInfo> out = new ArrayList<>();
        String sqlPeriph = """
                  SELECT id, name, base_addr
                    FROM peripherals
                   WHERE device_id = ?
                ORDER BY base_addr
                """;
        try (PreparedStatement psP = conn.prepareStatement(sqlPeriph)) {
            psP.setInt(1, deviceId);
            try (ResultSet rsP = psP.executeQuery()) {
                while (rsP.next()) {
                    int pid = rsP.getInt("id");
                    String pName = rsP.getString("name");
                    long pBase = rsP.getLong("base_addr");

                    /* 3) collect this peripheral’s registers (sorted) */
                    List<RegisterBrief> regs = new ArrayList<>();
                    long endAddr = pBase;           // default if no registers

                    try (PreparedStatement psR = conn.prepareStatement(
                            "SELECT name, base_addr                       " +
                                    "  FROM registers                             " +
                                    " WHERE peripheral_id = ?                    " +
                                    " ORDER BY base_addr")) {
                        psR.setInt(1, pid);
                        try (ResultSet rsR = psR.executeQuery()) {
                            while (rsR.next()) {
                                String rName = rsR.getString("name");
                                long rBase = rsR.getLong("base_addr");
                                regs.add(new RegisterBrief(rName, rBase));
                                endAddr = rBase;     // last row = highest address
                            }
                        }
                    }

                    out.add(new PeripheralInfo(pName, pBase, endAddr + 4, regs)); // TODO respect reg size
                }
            }
        } catch (SQLException ex) {
            throw new RuntimeException("peripherals query failed", ex);
        }

        return out;
    }

    // ───────────────── housekeeping ─────────────────
    @Override
    public void close() {
        try {
            conn.close();
        } catch (SQLException ignore) {
        }
    }

    // ───────────────── record helpers ───────────────
    public record PeripheralInfo(String name, long baseAddr, long endAddr,
                                 List<RegisterBrief> registers) {
    }

    public record RegisterBrief(String name, long baseAddr) {
    }

    public record RegisterInfo(String peripheral, long baseAddr,
                               String register, int sigId, List<FieldInfo> fields) {
    }

    public record FieldInfo(String name, int lsb, int msb) {
    }

    public record AddressHit(long address, int deviceId, int signatureId) {
    }
}
