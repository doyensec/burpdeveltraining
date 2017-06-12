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
        callbacks.issueAlert('Once again, Hello Burp!')  # Alerts tab

        # 2 - Use getStdout and getStderr to instantiate two PrintWriter instances
        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        stdout.println('Hello Burp in StdOut!')  # StdOut (either terminal, file or Burp's UI)
        stderr.println('Hello Burp in StdErr!')  # StdErr (either terminal, file or Burp's UI)

        # XXX: It is not possible to use the "friendly" accessors in python
        # XXX: it is therefore necessary to pass the callback object during HelloBurpTab construction
        # 3 - Instantiate a custom ITab implementation and add the tab to Burp (tip: use addSuiteTab)
        callbacks.addSuiteTab(HelloBurpTab(self.callbacks))  # Custom tab with custom UI components

class HelloBurpTab(ITab):
    def __init__(self, callbacks):
        self.callbacks = callbacks

    def getTabCaption(self):
        # TODO
        pass

    def getUiComponent(self):
        # TODO
        pass
