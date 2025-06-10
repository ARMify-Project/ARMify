package armify.view;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JSplitPane;

import docking.WindowPosition;
import docking.widgets.EmptyBorderButton;
import docking.widgets.OkDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import resources.ResourceManager;
import armify.controller.ARMifyController;
import armify.controller.PluginValidator;

public class ARMifyComponentProvider extends ComponentProviderAdapter {
    private final ARMifyController controller = new ARMifyController(this);
    private JPanel mainPanel;
    private JPanel contentPanel;
    private Program currentProgram;

    public ARMifyComponentProvider(PluginTool tool, String owner) {
        super(tool, "ARMify Plugin", owner);
        buildMainPanel();
        Icon customIcon = ResourceManager.loadImage("images/logo.png");
        setIcon(customIcon);
        setDefaultWindowPosition(WindowPosition.WINDOW);
        setTitle("ARMify Plugin");
        setVisible(false); // only show via Window menu
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    @Override
    public void componentShown() {
        // Validate when user explicitly opens the provider
        if (!PluginValidator.isValid(currentProgram)) {
            OkDialog.showError(
                    "Unsupported Program",
                    "ARMifyPlugin supports only little-endian ARM binaries."
            );
            setVisible(false);
        }
    }

    public void locationChanged(Program program, ProgramLocation location) {
        this.currentProgram = program;
        if (program != null && location != null) {
            controller.updateContext(program, location);
        }
    }

    private void buildMainPanel() {
        // Tree on the left as view selector
        GTree tree = new GTree(new RootNode());
        tree.setRootVisible(true);
        tree.addGTreeSelectionListener(event -> {
            Object node = event.getNewLeadSelectionPath().getLastPathComponent();
            String tabName = node.toString();
            switchPanel(tabName);
        });

        // Content area on right
        contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(defaultPanel(), BorderLayout.CENTER);

        // Split pane container
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tree, contentPanel);
        split.setDividerLocation(165);

        // Main panel layout
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        mainPanel.add(split, BorderLayout.CENTER);
    }

    private void switchPanel(String name) {
        JPanel view = switch (name) {
            case "MMIO Addresses" -> controller.buildMMIOAddressesView();
            case "Candidate Groups" -> controller.buildCandidateGroupsView();
            default -> defaultPanel();
        };
        contentPanel.removeAll();
        contentPanel.add(view, BorderLayout.CENTER);
        contentPanel.revalidate();
        contentPanel.repaint();
    }

    private JPanel defaultPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        panel.setBorder(BorderFactory.createTitledBorder("Default View"));
        panel.add(new EmptyBorderButton("Nothing to display"));
        return panel;
    }

    private static class RootNode extends GTreeNode {
        @Override
        public String getName() {
            return "ARMify";
        }

        @Override
        public List<GTreeNode> generateChildren() {
            List<GTreeNode> children = new ArrayList<>();
            children.add(new PanelNode("MMIO Addresses"));
            children.add(new PanelNode("Candidate Groups"));
            return children;
        }

        @Override
        public boolean isLeaf() {
            return false;
        }

        @Override
        public Icon getIcon(boolean expanded) {
            return null;
        }

        @Override
        public String getToolTip() {
            return "Select a view";
        }
    }

    private static class PanelNode extends GTreeNode {
        private final String name;

        PanelNode(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean isLeaf() {
            return true;
        }

        @Override
        public List<GTreeNode> generateChildren() {
            return new ArrayList<>();
        }

        @Override
        public Icon getIcon(boolean expanded) {
            return null;
        }

        @Override
        public String getToolTip() {
            return name + " View";
        }

        @Override
        public String toString() {
            return name;
        }
    }
}