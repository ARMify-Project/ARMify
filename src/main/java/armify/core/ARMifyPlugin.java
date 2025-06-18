package armify.core;

import armify.services.*;
import armify.ui.ARMifyProvider;
import armify.util.ProgramValidator;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = ExamplesPluginPackage.NAME,
        category = PluginCategoryNames.EXAMPLES,
        shortDescription = "ARMify plugin",
        description = "Identify Cortex-M MCUs from MMIO patterns"
)
public class ARMifyPlugin extends ProgramPlugin {

    private final ARMifyProvider provider;

    public ARMifyPlugin(PluginTool tool) {
        super(tool);

        /* shared, stateless helpers ------------------------------------ */
        ProgramStorageService programStorageService = new ProgramStorageService();

        DatabaseService databaseService = new DatabaseService();
        DeviceGroupingService deviceGroupingService = new DeviceGroupingService(databaseService);
        MatchingEngine matchingEngine = new MatchingEngine(databaseService, deviceGroupingService);

        ProgramAnalysisService programAnalysisService = new ProgramAnalysisService();
        ProgramInitializationService programInitializationService =
                new ProgramInitializationService(programAnalysisService, programStorageService);

        provider = new ARMifyProvider(
                tool, getName(), matchingEngine, programInitializationService, programStorageService);
        tool.addComponentProvider(provider, false);
        provider.registerInitialActions();
    }

    /* programme lifecycle ---------------------------------------------- */
    @Override
    protected void programActivated(Program program) {
        if (!ProgramValidator.isValid(program)) {
            provider.setProgramReference(null);
            return;
        }
        provider.setProgramReference(program);   // no init yet, happens on first show
    }

    @Override
    protected void locationChanged(ProgramLocation programLocation) {
        provider.onLocationChanged(currentProgram, programLocation);
    }
}