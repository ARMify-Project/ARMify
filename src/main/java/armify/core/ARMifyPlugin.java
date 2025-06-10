package armify.core;

import armify.services.DatabaseService;
import armify.services.ProgramAnalysisService;
import armify.services.MatchingEngine;
import armify.services.DeviceGroupingService;
import armify.ui.ARMifyProvider;
import armify.util.ProgramValidator;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;

@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = ExamplesPluginPackage.NAME,
        category = PluginCategoryNames.EXAMPLES,
        shortDescription = "ARMify Plugin",
        description = "Identifies Cortex-M microcontrollers from MMIO address patterns"
)
public class ARMifyPlugin extends ProgramPlugin {

    private ARMifyProvider provider;
    private ProgramAnalysisService analysisService;
    private DatabaseService databaseService;
    private MatchingEngine matchingEngine;

    public ARMifyPlugin(PluginTool tool) {
        super(tool);
        initializeServices();
        initializeUI();
    }

    private void initializeServices() {
        databaseService = new DatabaseService();
        DeviceGroupingService groupingService = new DeviceGroupingService(databaseService);
        matchingEngine = new MatchingEngine(databaseService, groupingService);
        analysisService = new ProgramAnalysisService();
    }

    private void initializeUI() {
        provider = new ARMifyProvider(tool, getName(), analysisService, matchingEngine);
        tool.addComponentProvider(provider, false);
    }

    @Override
    protected void locationChanged(ProgramLocation location) {
        if (provider != null && ProgramValidator.isValid(currentProgram)) {
            provider.onLocationChanged(currentProgram, location);
        }
    }

    @Override
    public void dispose() {
        if (provider != null) {
            provider.setVisible(false);
        }
        if (databaseService != null) {
            databaseService.close();
        }
    }
}
