package armify.services;

import armify.domain.EventBus;
import armify.domain.MMIOAccessEntry;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

import static armify.util.ProgramMemory.*;

/**
 * One-time preparation (clear edits, create peripheral block, auto-analysis) and
 * subsequent MMIO loading. Returns {@code true} when the program is ready.
 */
public class ProgramInitializationService {
    private final ProgramAnalysisService analysisService;
    private final ProgramStorageService storage;

    public ProgramInitializationService(ProgramAnalysisService analysisService,
                                        ProgramStorageService storage) {
        this.analysisService = analysisService;
        this.storage = storage;
    }

    /* ------------------------------------------------------------------ */
    /* Entry-point                                                        */
    /* ------------------------------------------------------------------ */
    public boolean ensureInitialised(PluginTool tool, Program program, EventBus eventBus) {
        if (program == null) {
            return false;
        }

        // First run of the plugin
        if (!storage.isInitialised(program)) {
            return handleFirstRun(tool, program, eventBus);
        }

        // Not the first run of the plugin
        List<MMIOAccessEntry> accesses = storage.loadMMIOAccesses(program);
        eventBus.publish(new armify.ui.events.AnalysisCompleteEvent(accesses));

        return true;
    }

    private boolean handleFirstRun(PluginTool tool, Program program, EventBus eventBus) {
        List<MMIOAccessEntry> accesses;
        long stack_pointer;
        long reset_vector;

        // 1. Get stack pointer and reset vector
        try {
            ArrayList<Long> results = getSPAndResetVector(program);
            stack_pointer = results.get(0);
            reset_vector = results.get(1);
        } catch (MemoryAccessException e) {
            Msg.error(this, "Can't read first eight bytes of program", e);
            return false;
        }

        // 2. Validate Cortex-M
        if (!validateCortexM(stack_pointer, reset_vector)) {
            Msg.error(this, String.format(
                    "Program doesn't look like a Cortex-M firmware (SP=0x%08X, RV=0x%08X)",
                    stack_pointer, reset_vector));
            return false;
        }

        // 3. Ask user for confirmation before continuing
        if (!askUserForConfirmation(tool)) return false;

        // 4. Execute changes to program database
        int tx = program.startTransaction("ARMify prepare");
        boolean commit = false;
        try {
            removeUserBlocks(program);

            if (isRawBinary(program)) {
                handleRawBinaryRelocation(program, reset_vector);
            }

            markVectorTableHeader(program);
            createPeripheralBlock(program);
            commit = true;
        } catch (Exception ex) {
            Msg.error(this, "First run initialisation error", ex);
        } finally {
            program.endTransaction(tx, commit);
        }
        if (!commit) {
            return false;
        }

        // 5. Run the auto analysis and permanently mark program as analyzed
        runAutoAnalysis(program, tool);
        GhidraProgramUtilities.markProgramAnalyzed(program);

        // 6. Identify MMIO accesses
        try {
            accesses = analysisService.scanMMIOAccesses(program, TaskMonitor.DUMMY);
        } catch (CancelledException e) {
            return false;
        }

        // 7. Store the accesses and the initialised flag
        storage.saveMMIOAccesses(program, accesses);
        storage.setInitialised(program, true);

        // 8. Raise AnalysisCompleteEvent notification
        eventBus.publish(new armify.ui.events.AnalysisCompleteEvent(accesses));

        return true;
    }


    private boolean validateCortexM(long stack_pointer, long reset_vector) {
        // Valid SRAM address range for the stack pointer
        final long SRAM_START = 0x20000000L;
        final long SRAM_END = 0x3FFFFFFFL;

        // Valid code (flash) address range for the reset vector
        final long CODE_START = 0x00000000L;
        final long CODE_END = 0x1FFFFFFFL;

        // Check: Stack pointer must be in SRAM
        if (stack_pointer < SRAM_START || stack_pointer > SRAM_END) {
            return false;
        }

        // Check: Reset vector must be in code region and have LSB = 1 (Thumb mode)
        if ((reset_vector & 1) == 0) {
            return false; // Not a valid Thumb address
        }

        long reset_address = reset_vector & ~1L; // Clear LSB to get actual address

        //noinspection RedundantIfStatement
        if (reset_address < CODE_START || reset_address > CODE_END) {
            return false;
        }

        return true;
    }

    private boolean askUserForConfirmation(PluginTool tool) {
        String msg = """
                ARMify will prepare this program:
                
                 • Clear user-created memory blocks
                 • Create a 0x4000_0000-0x5FFF_FFFF “peripheral” block
                 • Run auto-analysis (incl. ARM Aggressive IF)
                 • Scan MMIO accesses
                
                Warning – existing analysis work might be lost.
                
                Continue?""";

        int result = OptionDialog.showYesNoDialog(tool.getToolFrame(), "ARMify initialisation", msg);
        return result == OptionDialog.YES_OPTION;
    }

    private boolean isRawBinary(Program p) {
        String fmt = p.getExecutableFormat();
        return fmt != null && fmt.toLowerCase().contains("raw binary");
    }

    private void handleRawBinaryRelocation(Program program, long resetVector)
            throws MemoryConflictException, AddressOverflowException, LockException, MemoryBlockException, NotFoundException {
        Memory memory = program.getMemory();
        List<MemoryBlock> blocks = List.of(memory.getBlocks());

        // 1. Check if there is exactly one block
        if (blocks.size() != 1) {
            throw new MemoryConflictException(
                    "Expected exactly one raw-binary block, but found " + blocks.size());
        }

        MemoryBlock block = blocks.getFirst();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

        // 2. Decide base by reset vector
        long resetAddress = resetVector & ~1L;  // clear Thumb bit
        final long NON_ZERO_FLASH_LOAD_ADDRESS = 0x0800_0000L;
        boolean useNonZeroFlashBase = resetAddress >= NON_ZERO_FLASH_LOAD_ADDRESS;

        // 3. Move block if necessary
        Address newBase = space.getAddress(useNonZeroFlashBase ? NON_ZERO_FLASH_LOAD_ADDRESS : 0L);
        if (!block.getStart().equals(newBase)) {
            memory.moveBlock(block, newBase, TaskMonitor.DUMMY);
        }

        // 4. Rename the block
        block.setName("flash");

        // 5. If the flash is mapped to non-zero, mirror the first bytes to 0x0
        if (useNonZeroFlashBase) {
            int mirrorLen = (int) Math.min(block.getSize(), NON_ZERO_FLASH_LOAD_ADDRESS);
            Address mirrorAt = space.getAddress(0L);
            MessageLog log = new MessageLog();
            MemoryBlock mirror = MemoryBlockUtils.createByteMappedBlock(
                    program,
                    "flash_mirror",    // name
                    mirrorAt,          // start @ 0x0
                    newBase,           // base = flash block’s new start
                    mirrorLen,         // length in bytes
                    "Flash mirror",    // comment
                    "ARMify Plugin",   // source
                    true,    // r
                    false,   // w
                    block.isExecute(), // x
                    false,             // overlay?
                    log
            );
            if (mirror == null) {
                throw new MemoryConflictException(
                        "Failed to create flash mirror: " + log);
            }
        }
    }

    private void markVectorTableHeader(Program program) throws CodeUnitInsertionException {
        Listing listing = program.getListing();
        Address base = program.getMinAddress();
        PointerDataType ptr32 =
                new PointerDataType(VoidDataType.dataType, 4,
                        program.getDataTypeManager());

        // Stack pointer
        DataUtilities.createData(program, base, ptr32, 1, false,
                DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
        listing.getCodeUnitAt(base)
                .setComment(CodeUnit.EOL_COMMENT, "Initial SP (stack-top)");

        // Reset vector
        Address reset_vector = base.add(4);
        DataUtilities.createData(program, reset_vector, ptr32, 1, false,
                DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
        listing.getCodeUnitAt(reset_vector)
                .setComment(CodeUnit.EOL_COMMENT, "Reset vector (initial PC, Thumb)");
    }

    private void runAutoAnalysis(Program program, PluginTool tool) {
        Task analysisTask = new Task("ARMify – auto-analysis", false, false, true) {
            @Override
            public void run(TaskMonitor monitor) {
                // 1. Reset all analysis options in one transaction and enable ARM Aggressive Instruction Finder
                int txId = program.startTransaction("ARMify – reset analysis options");
                try {
                    Options opts = program.getOptions(Program.ANALYSIS_PROPERTIES);
                    for (String name : opts.getOptionNames()) {
                        opts.restoreDefaultValue(name);
                    }
                    opts.setBoolean("ARM Aggressive Instruction Finder", true);
                } finally {
                    program.endTransaction(txId, true);
                }

                // 2. Re-analyze everything and wait until the analysis is finished
                AutoAnalysisManager autoAnalysisManager = AutoAnalysisManager.getAnalysisManager(program);
                AddressSetView allInitializedAddressSet = program.getMemory().getLoadedAndInitializedAddressSet();
                autoAnalysisManager.initializeOptions(); // reload the options since we changed them
                autoAnalysisManager.reAnalyzeAll(allInitializedAddressSet);
                autoAnalysisManager.waitForAnalysis(null, monitor);
            }
        };

        new TaskLauncher(analysisTask, tool.getToolFrame());
    }
}