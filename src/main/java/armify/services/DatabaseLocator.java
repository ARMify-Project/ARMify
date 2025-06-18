package armify.services;

import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.nio.file.*;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

import com.github.luben.zstd.ZstdInputStream;

/**
 * Locates (or lazily extracts) the runtime SQLite database from User settings dir
 * ${Application.getUserSettingsDirectory()}/armify/database.sqlite
 */
public final class DatabaseLocator {
    private static final String RES_PATH = "/db/database.sqlite.zst";

    private static final String SUBDIR = "armify";
    private static final String DB_NAME = "database.sqlite";
    private static final String SHA1_NAME = DB_NAME + ".sha1";

    private DatabaseLocator() {
        /* utility class */
    }

    /**
     * Resolves the database file path (extracting it if necessary).
     * Call once during plugin start-up.
     */
    public static Path resolveOrExtract() {
        File userSettings = Application.getUserSettingsDirectory();
        Path armifyDir = userSettings.toPath().resolve(SUBDIR);
        Path sqliteFile = armifyDir.resolve(DB_NAME);

        try {
            if (Files.exists(sqliteFile) && isUpToDate(sqliteFile)) {
                return sqliteFile;
            }
        } catch (IOException io) {
            Msg.error(DatabaseLocator.class,
                    "Failed SHA-1 check on existing DB, will re-extract", io);
        }

        // extract with a progress dialog
        Task t = new Task("Unpacking ARMify runtime database", false, false, true) {
            @Override
            public void run(TaskMonitor mon) throws CancelledException {
                try {
                    unpackTo(sqliteFile, mon);
                } catch (IOException ex) {
                    Msg.error("Failed unpacking ARMify runtime database", ex);
                }
            }
        };
        new TaskLauncher(t, null);

        return sqliteFile;
    }

    private static boolean isUpToDate(Path sqlite) throws IOException {
        Path shaFile = sqlite.resolveSibling(SHA1_NAME);
        if (!Files.exists(shaFile)) {
            return false;
        }
        String stored = Files.readString(shaFile);
        String fresh = resourceSha1();
        return stored.equals(fresh);
    }

    private static void unpackTo(Path target, TaskMonitor mon) throws IOException, CancelledException {
        Files.createDirectories(target.getParent());

        try (InputStream in = Objects.requireNonNull(
                DatabaseLocator.class.getResourceAsStream(RES_PATH),
                "Embedded DB asset " + RES_PATH + " missing");
             ZstdInputStream zIn = new ZstdInputStream(in);
             OutputStream out = Files.newOutputStream(target,
                     StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {

            mon.initialize(-1);
            byte[] buf = new byte[1 << 20]; // 1 MiB chunks
            int n;
            while ((n = zIn.read(buf)) > 0) {
                mon.checkCancelled();
                out.write(buf, 0, n);
                mon.incrementProgress(n);
            }
        }

        // store new SHA-1
        Files.writeString(target.resolveSibling(SHA1_NAME), resourceSha1());
        Msg.info(DatabaseLocator.class, "ARMify DB extracted to " + target);
    }

    private static String resourceSha1() throws IOException {
        try (InputStream in = DatabaseLocator.class.getResourceAsStream(RES_PATH)) {
            if (in == null) {
                throw new IOException("Cannot find resource " + RES_PATH);
            }

            MessageDigest md = MessageDigest.getInstance("SHA-1");
            in.transferTo(new DigestOutputStream(OutputStream.nullOutputStream(), md));
            return HexFormat.of().withUpperCase().formatHex(md.digest());
        } catch (NoSuchAlgorithmException ex) {
            throw new IOException("Unable to hash embedded DB", ex);
        }
    }
}
