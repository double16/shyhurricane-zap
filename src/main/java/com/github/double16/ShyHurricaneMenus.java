package com.github.double16;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JTree;
import javax.swing.tree.TreePath;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionHookMenu;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.messagecontainer.http.SelectableHistoryReferencesContainer;
import org.zaproxy.zap.view.messagecontainer.http.SingleHistoryReferenceContainer;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuComponent;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

final class ShyHurricaneMenus {
    private static final String LABEL = "Send to ShyHurricane";

    private ShyHurricaneMenus() {}

    static void register(final ExtensionHookMenu menu, final ManualSendService sender) {
        menu.addPopupMenuItem(new Alerts(sender));
        menu.addPopupMenuItem(new Messages(sender));
    }

    static final class Alerts extends ExtensionPopupMenuItem {
        private JTree selectionTree;

        Alerts(final ManualSendService sender) {
            super(LABEL);
            addActionListener(
                    event -> {
                        final List<Alert> selection =
                                selectedAlerts(
                                        selectionTree == null
                                                ? null
                                                : selectionTree.getSelectionPaths());
                        selectionTree = null;
                        sender.sendAlerts(selection);
                    });
        }

        @Override
        public boolean isSafe() {
            return true;
        }

        @Override
        public boolean isEnableForComponent(final Component component) {
            selectionTree = null;
            if (component instanceof JTree tree && "treeAlert".equals(tree.getName())) {
                selectionTree = tree;
                setEnabled(!selectedAlerts(tree.getSelectionPaths()).isEmpty());
                return true;
            }
            return false;
        }

        @Override
        public void dismissed(final ExtensionPopupMenuComponent selected) {
            if (selected != this) {
                selectionTree = null;
            }
        }
    }

    static final class Messages extends PopupMenuItemHttpMessageContainer {
        private final ManualSendService sender;

        Messages(final ManualSendService sender) {
            super(LABEL, true);
            this.sender = sender;
        }

        @Override
        public boolean isSafe() {
            return true;
        }

        @Override
        protected boolean isEnableForInvoker(
                final Invoker invoker, final HttpMessageContainer container) {
            return invoker != Invoker.ALERTS_PANEL;
        }

        @Override
        protected boolean isButtonEnabledForHttpMessageContainerState(
                final HttpMessageContainer container) {
            if (getInvoker() == Invoker.SITES_PANEL
                    && container.getComponent() instanceof JTree tree) {
                return tree.getSelectionCount() > 0;
            }
            // Do not load database-backed messages just to open a popup.
            return isButtonEnabledForNumberOfSelectedMessages(container);
        }

        @Override
        protected void performActions(final HttpMessageContainer container) {
            if (getInvoker() == Invoker.SITES_PANEL
                    && container.getComponent() instanceof JTree tree) {
                sender.sendHistory(siteReferences(tree.getSelectionPaths()));
            } else if (container instanceof SelectableHistoryReferencesContainer references) {
                sender.sendHistory(List.copyOf(references.getSelectedHistoryReferences()));
            } else if (container instanceof SingleHistoryReferenceContainer reference) {
                final HistoryReference history = reference.getHistoryReference();
                sender.sendHistory(history == null ? List.of() : List.of(history));
            } else {
                super.performActions(container);
            }
        }

        @Override
        protected void performActions(final List<HttpMessage> messages) {
            sender.sendMessages(messages);
        }

        @Override
        protected void performAction(final HttpMessage message) {
            sender.sendMessages(List.of(message));
        }
    }

    static List<HistoryReference> siteReferences(final TreePath[] paths) {
        final List<HistoryReference> references = new ArrayList<>();
        if (paths != null) {
            for (final TreePath path : paths) {
                if (path.getLastPathComponent() instanceof SiteNode node) {
                    final var nodes = node.depthFirstEnumeration();
                    while (nodes.hasMoreElements()) {
                        final SiteNode descendant = (SiteNode) nodes.nextElement();
                        if (descendant.getHistoryReference() != null) {
                            references.add(descendant.getHistoryReference());
                        }
                    }
                }
            }
        }
        return List.copyOf(references);
    }

    static List<Alert> selectedAlerts(final TreePath[] paths) {
        final List<Alert> alerts = new ArrayList<>();
        if (paths != null) {
            for (final TreePath path : paths) {
                if (path.getLastPathComponent() instanceof AlertNode node) {
                    final var nodes = node.depthFirstEnumeration();
                    while (nodes.hasMoreElements()) {
                        final AlertNode descendant = (AlertNode) nodes.nextElement();
                        if (descendant.isLeaf() && descendant.getAlert() != null) {
                            alerts.add(descendant.getAlert());
                        }
                    }
                }
            }
        }
        return List.copyOf(alerts);
    }
}
