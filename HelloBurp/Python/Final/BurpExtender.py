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

        callbacks.issueAlert('Once again, Hello Burp!')  # Alerts tab

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        stdout.println('Hello Burp in StdOut!')  # StdOut (either terminal, file or Burp's UI)
        stderr.println('Hello Burp in StdErr!')  # StdErr (either terminal, file or Burp's UI)

        # XXX: It is not possible to use the "friendly" accessors in python
        # XXX: it is therefore necessary to pass the callback object during HelloBurpTab construction
        callbacks.addSuiteTab(HelloBurpTab(self.callbacks))  # Custom tab with custom UI components

class HelloBurpTab(ITab):
    def __init__(self, callbacks):
        self.callbacks = callbacks

    def getTabCaption(self):
        return 'Hello Burp Tab!'

    def getUiComponent(self):
        panel = Panel()
        panel.setBackground(Color.gray)
        button = Button('Hello Burp Button!')
        panel.add(button)
        self.callbacks.customizeUiComponent(panel)  # customize UI components in line with Burp's UI style
        return panel
