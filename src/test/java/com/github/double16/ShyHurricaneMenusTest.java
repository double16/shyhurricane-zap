package com.github.double16;

import static com.github.double16.ForwardingTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.List;
import javax.swing.JLabel;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.extension.ExtensionHookMenu;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.messagecontainer.http.SelectableHistoryReferencesContainer;
import org.zaproxy.zap.view.messagecontainer.http.SelectableHttpMessagesContainer;
import org.zaproxy.zap.view.messagecontainer.http.SingleHistoryReferenceContainer;
import org.zaproxy.zap.view.messagecontainer.http.SingleHttpMessageContainer;

class ShyHurricaneMenusTest {
    @Test
    void registersTwoMenusWithSameClearLabel() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            final ExtensionHookMenu hook = mock(ExtensionHookMenu.class);
            ShyHurricaneMenus.register(hook, support.sender);
            final var menus = org.mockito.ArgumentCaptor.forClass(ExtensionPopupMenuItem.class);
            verify(hook, times(2)).addPopupMenuItem(menus.capture());
            assertEquals(2, menus.getAllValues().size());
            for (final var menu : menus.getAllValues()) {
                assertEquals("Send to ShyHurricane", menu.getText());
                assertTrue(
                        menu.isSafe(),
                        "Sending stored data does not attack the target or require scope checks");
            }
        }
    }

    @Test
    void alertMenuExpandsNestedGroupsIncludingRootAndHandlesOverlaps() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            final AlertNode root =
                    new AlertNode(
                            0, "Alerts", java.util.Comparator.comparing(AlertNode::getNodeName));
            final AlertNode group =
                    new AlertNode(
                            0,
                            "Risk group",
                            java.util.Comparator.comparing(AlertNode::getNodeName));
            final AlertNode subgroup =
                    new AlertNode(
                            0,
                            "Rule group",
                            java.util.Comparator.comparing(AlertNode::getNodeName));
            final AlertNode leaf =
                    new AlertNode(
                            0, "Alert", java.util.Comparator.comparing(AlertNode::getNodeName));
            leaf.setAlert(alert(1, message()));
            root.add(group);
            group.add(subgroup);
            subgroup.add(leaf);
            final JTree tree = new JTree(root);
            tree.setName("treeAlert");
            final var menu = new ShyHurricaneMenus.Alerts(support.sender);
            SwingUtilities.invokeAndWait(
                    () -> {
                        tree.setSelectionPaths(
                                new TreePath[] {
                                    new TreePath(root.getPath()), new TreePath(leaf.getPath())
                                });
                        assertTrue(menu.isEnableForComponent(tree));
                        assertTrue(menu.isEnabled());
                        menu.dismissed(menu);
                        menu.doClick(0);
                    });
            assertTrue(support.completed().text().contains("1 findings and 1 HTTP exchanges"));
            assertEquals(2, support.deliveries.size());
            SwingUtilities.invokeAndWait(
                    () -> {
                        tree.clearSelection();
                        assertTrue(menu.isEnableForComponent(tree));
                        assertFalse(menu.isEnabled());
                        assertFalse(menu.isEnableForComponent(new JLabel()));
                        tree.setName("unrelated");
                        assertFalse(menu.isEnableForComponent(tree));
                        menu.dismissed(null);
                    });
            assertTrue(ShyHurricaneMenus.selectedAlerts(null).isEmpty());
            assertTrue(
                    ShyHurricaneMenus.selectedAlerts(
                                    new TreePath[] {new TreePath(new DefaultMutableTreeNode())})
                            .isEmpty());
            assertTrue(
                    ShyHurricaneMenus.selectedAlerts(
                                    new TreePath[] {
                                        new TreePath(
                                                new AlertNode(
                                                        0,
                                                        "empty",
                                                        java.util.Comparator.comparing(
                                                                AlertNode::getNodeName)))
                                    })
                            .isEmpty());
        }
    }

    @Test
    void sitesMenuExpandsFoldersAndCurrentReferencesWithoutLoadingMessagesOnEdt() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            final HistoryReference first = mock(HistoryReference.class);
            when(first.getHistoryId()).thenReturn(1);
            when(first.getHttpMessage())
                    .thenAnswer(
                            invocation -> {
                                assertFalse(SwingUtilities.isEventDispatchThread());
                                return message();
                            });
            final SiteNode root = new SiteNode(null, 0, "Sites");
            final SiteNode folder = new SiteNode(null, 0, "Folder");
            final SiteNode leaf = new SiteNode(null, 0, "Leaf");
            leaf.setHistoryReference(first);
            root.add(folder);
            folder.add(leaf);
            final JTree tree = new JTree(root);
            final var container = mock(SelectableHistoryReferencesContainer.class);
            when(container.getName()).thenReturn("treeSite");
            when(container.getComponent()).thenReturn(tree);
            final var menu = new ShyHurricaneMenus.Messages(support.sender);
            SwingUtilities.invokeAndWait(
                    () -> {
                        tree.setSelectionPaths(
                                new TreePath[] {
                                    new TreePath(folder.getPath()), new TreePath(leaf.getPath())
                                });
                        assertTrue(menu.isEnableForMessageContainer(container));
                        assertTrue(menu.isEnabled());
                        menu.doClick(0);
                    });
            assertTrue(support.completed().text().contains("1 HTTP exchanges"));
            verify(first, times(1)).getHttpMessage();
            SwingUtilities.invokeAndWait(
                    () -> {
                        tree.clearSelection();
                        assertTrue(menu.isEnableForMessageContainer(container));
                        assertFalse(menu.isEnabled());
                    });
            assertTrue(ShyHurricaneMenus.siteReferences(null).isEmpty());
            assertTrue(
                    ShyHurricaneMenus.siteReferences(new TreePath[] {new TreePath("unrelated")})
                            .isEmpty());
        }
    }

    @Test
    void httpMenuSupportsSingleAndMultipleViewersAndAvailableResultsPanels() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            final var menu = new ShyHurricaneMenus.Messages(support.sender);
            final var single = mock(SingleHttpMessageContainer.class);
            when(single.getName()).thenReturn("Request viewer");
            when(single.getMessage()).thenReturn(message());
            SwingUtilities.invokeAndWait(
                    () -> {
                        assertTrue(menu.isEnableForMessageContainer(single));
                        assertTrue(menu.isEnabled());
                        menu.doClick(0);
                    });
            assertTrue(support.completed().text().contains("1 HTTP exchanges"));
            when(single.isEmpty()).thenReturn(true);
            assertTrue(menu.isEnableForMessageContainer(single));
            assertFalse(menu.isEnabled());
            final var multiple = mock(SelectableHttpMessagesContainer.class);
            when(multiple.getNumberOfSelectedMessages()).thenReturn(2);
            when(multiple.getSelectedMessages())
                    .thenAnswer(invocation -> List.of(message(), message()));
            for (final String panel :
                    List.of(
                            "History Table",
                            "SearchHttpMessageContainer",
                            "ActiveScanMessageContainer",
                            "SpiderHttpMessageContainer",
                            "ForcedBrowseMessageContainer",
                            "fuzz.httpfuzzerResultsContentPanel",
                            "Response viewer")) {
                when(multiple.getName()).thenReturn(panel);
                SwingUtilities.invokeAndWait(
                        () -> {
                            assertTrue(menu.isEnableForMessageContainer(multiple), panel);
                            assertTrue(menu.isEnabled(), panel);
                            menu.doClick(0);
                        });
                assertTrue(support.completed().text().contains("2 HTTP exchanges"));
            }
            when(multiple.getName()).thenReturn("treeAlert");
            assertFalse(
                    menu.isEnableForMessageContainer(multiple),
                    "The dedicated alert menu owns this location");
            assertFalse(menu.isEnableForMessageContainer(mock(HttpMessageContainer.class)));
            menu.performAction(message());
            assertTrue(support.completed().text().contains("1 HTTP exchanges"));
        }
    }

    @Test
    void historyContainersCaptureReferencesAndPermitEmptySelections() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            final var menu = new ShyHurricaneMenus.Messages(support.sender);
            final HistoryReference reference = mock(HistoryReference.class);
            when(reference.getHttpMessage()).thenReturn(message());
            final var single = mock(SingleHistoryReferenceContainer.class);
            when(single.getName()).thenReturn("single history");
            when(single.getHistoryReference()).thenReturn(reference);
            menu.performActions(single);
            assertTrue(support.completed().text().contains("1 HTTP exchanges"));
            when(single.getHistoryReference()).thenReturn(null);
            menu.performActions(single);
            assertTrue(support.completed().text().contains("0 HTTP exchanges"));
            final var multiple = mock(SelectableHistoryReferencesContainer.class);
            when(multiple.getName()).thenReturn("History Table");
            when(multiple.getNumberOfSelectedMessages()).thenReturn(2);
            when(multiple.getSelectedHistoryReferences()).thenReturn(List.of(reference, reference));
            assertTrue(menu.isEnableForMessageContainer(multiple));
            menu.performActions(multiple);
            assertTrue(support.completed().text().contains("1 HTTP exchanges"));
            verify(multiple, never()).getSelectedMessages();
            // A Sites-named add-on container without a tree still uses its public reference
            // interface.
            when(multiple.getName()).thenReturn("treeSite");
            assertTrue(menu.isEnableForMessageContainer(multiple));
            menu.performActions(multiple);
            assertTrue(support.completed().text().contains("1 HTTP exchanges"));
        }
    }
}
