#
# HelloBurp - A simple extension to show alerts, stdout/stderr and custom UI
#
# Copyright (c) 2017 Doyensec LLC. Made with love by Andrea Brancaleoni.
#

from burp import IBurpExtender, ITab
from java.awt import Button, Color, Panel
from java.io import PrintWriter


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName('Hello Burp!')

        # 1 - Use issueAlert to trigger an alert
        # 2 - Use getStdout and getStderr to instantiate two PrintWriter instances
        # 3 - Instantiate a custom ITab implementation and add the tab to Burp (tip: use addSuiteTab)


class HelloBurpTab(ITab):
    def __init__(self, callbacks):
        self.callbacks = callbacks

    def getTabCaption(self):
        # TODO
        pass

    def getUiComponent(self):
        # TODO
        pass
