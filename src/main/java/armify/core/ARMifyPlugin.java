package armify.core;

import armify.services.*;
import armify.ui.ARMifyProvider;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

import java.nio.file.Path;

@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = ExamplesPluginPackage.NAME,
        category = PluginCategoryNames.EXAMPLES,
        shortDescription = "ARMify plugin",
        description = "Identify Cortex-M MCUs from MMIO patterns"
)
public class ARMifyPlugin extends ProgramPlugin {

    private final ARMifyProvider provider;
    private final DomainObjectListener domainObjectListener;

    public ARMifyPlugin(PluginTool tool) {
        super(tool);

        ProgramStorageService programStorageService = new ProgramStorageService();

        Path databasePath = DatabaseLocator.resolveOrExtract();
        DatabaseService databaseService = new DatabaseService(databasePath);
        MatchingEngine matchingEngine = new MatchingEngine(databaseService);

        ProgramAnalysisService programAnalysisService = new ProgramAnalysisService();
        ProgramInitializationService programInitializationService =
                new ProgramInitializationService(programAnalysisService, programStorageService);
        DeviceApplyService deviceApplyService =
                new DeviceApplyService(programStorageService, databaseService);

        provider = new ARMifyProvider(
                tool,
                getName(),
                matchingEngine,
                programInitializationService,
                programStorageService,
                programAnalysisService,
                deviceApplyService
        );

        tool.addComponentProvider(provider, false);
        provider.registerInitialActions();

        domainObjectListener = createDomainObjectListener();
    }

    private DomainObjectListener createDomainObjectListener() {
        return evt -> {
            if (!provider.isVisible() || !provider.isInitDone()) {
                return;
            }
            provider.publishListingChangedEvent(evt);
        };
    }

    @Override
    public void dispose() {
        if (currentProgram != null) {
            currentProgram.removeListener(domainObjectListener);
        }
    }

    @Override
    protected void programActivated(Program program) {
        if (program != null) {
            program.addListener(domainObjectListener);
        }

        provider.setProgramReference(program);   // no init yet, happens on first show

        if (provider.isVisible()) {
            provider.componentShown();
        }
    }

    @Override
    protected void programDeactivated(Program program) {
        if (program != null) {
            program.removeListener(domainObjectListener);
        }

        provider.setProgramReference(null);
    }

    @Override
    protected void locationChanged(ProgramLocation programLocation) {
        provider.onLocationChanged(currentProgram, programLocation);
    }
}