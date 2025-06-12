package armify.ui.components;

import armify.domain.EventBus;
import armify.ui.events.*;
import armify.ui.views.ViewType;
import docking.widgets.tree.*;
import docking.widgets.tree.support.GTreeSelectionEvent;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class NavigationTree {
    private final EventBus eventBus;
    private final GTree tree;

    public NavigationTree(EventBus eventBus) {
        this.eventBus = eventBus;

        tree = new GTree(new RootNode());
        tree.setRootVisible(false);
        tree.addGTreeSelectionListener(this::handleSelectionChanged);
    }

    private void handleSelectionChanged(GTreeSelectionEvent event) {
        Object node = event.getNewLeadSelectionPath().getLastPathComponent();
        if (node instanceof ViewNode viewNode) {
            eventBus.publish(new ViewSelectionEvent(viewNode.getViewType()));
        }
    }

    public JComponent getComponent() {
        return tree;
    }

    private static class RootNode extends GTreeNode {
        @Override
        public String getName() {
            return "ARMify Plugin";
        }

        @Override
        public List<GTreeNode> generateChildren() {
            List<GTreeNode> children = new ArrayList<>();
            children.add(new ViewNode(ViewType.MMIO_ADDRESSES));
            children.add(new ViewNode(ViewType.CANDIDATE_GROUPS));
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
            return "ARMify Plugin";
        }
    }

    private static class ViewNode extends GTreeNode {
        private final ViewType viewType;

        ViewNode(ViewType viewType) {
            this.viewType = viewType;
        }

        public ViewType getViewType() {
            return viewType;
        }

        @Override
        public String getName() {
            return viewType.getDisplayName();
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
            return viewType.getDisplayName() + " View";
        }

        @Override
        public String toString() {
            return getName();
        }
    }
}
