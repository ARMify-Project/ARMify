package armify.ui.views;

import docking.action.DockingAction;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

import javax.swing.JComponent;
import java.util.List;

public interface ViewComponent {
    JComponent getComponent();

    List<DockingAction> getViewActions();

    void installListeners(PluginTool tool, ComponentProviderAdapter provider);

}
