package armify;

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
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import resources.ResourceManager;

public class ARMifyComponentProvider extends ComponentProviderAdapter {
    private JPanel mainPanel;
    private JPanel contentPanel;
    private Program currentProgram = null;
    private ProgramLocation currentLocation = null;

    public ARMifyComponentProvider(PluginTool tool, String owner) {
        super(tool, "ARMify Plugin", owner);
        buildMainPanel();
        Icon customIcon = ResourceManager.loadImage("images/logo.png");
        setIcon(customIcon);
        setDefaultWindowPosition(WindowPosition.WINDOW);
        setTitle("ARMify Plugin");
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    void locationChanged(Program program, ProgramLocation location) {
        this.currentProgram = program;
        this.currentLocation = location;
    }

    @Override
    public void componentShown() {
        // Validate only when the user manually shows the provider via Window menu
        if (currentProgram == null) {
            OkDialog.showError(
                    "No Program Loaded",
                    "You must open a program before using the ARMify Plugin."
            );
            setVisible(false);
            return;
        }

        Language language = currentProgram.getLanguage();
        boolean isARM = language.getProcessor().toString().equalsIgnoreCase("ARM");
        boolean isLittleEndian = !language.isBigEndian();

        if (!isARM || !isLittleEndian) {
            OkDialog.showError(
                    "Unsupported Program",
                    "ARMifyPlugin supports only little-endian ARM binaries."
            );
            setVisible(false);
        }
    }

    private boolean isValidProgram(Program program) {
        if (program == null) return false;
        Language language = program.getLanguage();
        boolean isARM = language.getProcessor().toString().equalsIgnoreCase("ARM");
        boolean isLittleEndian = !language.isBigEndian();
        return isARM && isLittleEndian;
    }

    private void buildMainPanel() {
        // Tree on the left
        GTree tree = new GTree(new RootNode());
        tree.setRootVisible(true);

        // Content panel on the right
        contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(defaultPanel(), BorderLayout.CENTER);

        // Split pane: pass tree directly
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tree, contentPanel);
        split.setDividerLocation(200);

        // Main container
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        mainPanel.add(split, BorderLayout.CENTER);

        // Listen for selection changes using GTree listener
        tree.addGTreeSelectionListener(
                gTreeSelectionEvent -> switchPanel(
                        gTreeSelectionEvent.getNewLeadSelectionPath().getLastPathComponent().toString()
                )
        );
    }

    private JPanel defaultPanel() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.CENTER));
        p.setBorder(BorderFactory.createTitledBorder("Default View"));
        p.add(new EmptyBorderButton("Nothing to display"));
        return p;
    }

    private void switchPanel(String name) {
        contentPanel.removeAll();
        JPanel newView = switch (name) {
            case "View A" -> viewAPanel();
            case "View B" -> viewBPanel();
            default -> defaultPanel();
        };
        contentPanel.add(newView, BorderLayout.CENTER);
        contentPanel.revalidate();
        contentPanel.repaint();
    }

    private JPanel viewAPanel() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.CENTER));
        p.setBorder(BorderFactory.createTitledBorder("Panel A"));
        p.add(new EmptyBorderButton("Action A"));
        return p;
    }

    private JPanel viewBPanel() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.CENTER));
        p.setBorder(BorderFactory.createTitledBorder("Panel B"));
        p.add(new EmptyBorderButton("Action B"));
        return p;
    }

    private static class RootNode extends GTreeNode {
        @Override
        public String getName() {
            return "Tabs";
        }

        @Override
        public List<GTreeNode> generateChildren() {
            List<GTreeNode> children = new ArrayList<>();
            children.add(new PanelNode("View A"));
            children.add(new PanelNode("View B"));
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
            return "Tabs tooltip";
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
            return name + " tooltip";
        }

        @Override
        public String toString() {
            return name;
        }
    }
}