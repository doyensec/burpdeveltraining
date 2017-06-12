#
# DetectELJ - Active scanner extension to detect Expression Language Injection vulnerabilities
#
# Copyright (c) 2017 Doyensec LLC. Made with love by Andrea Brancaleoni.
#
from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, Arrays, List

from org.python.core.util import StringUtil
from jarray import array


class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName('DetectELJ')

        callbacks.issueAlert('DetectELJ Active Scanner check enabled')

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, ihrr):
        return None # Active scanner check only

    def doActiveScan(self, ihrr, isip):
        # 1 - Create a new request with our custom payload (tip: buildRequest)

        # 2 - Send the HTTP request

        # 3 - Diff original and new responses (tip: analyzeResponseVariations and getVariantAttributes)

        # 4 - Based on page changes, determine whether the page is vulnerable or not

        # 5 - If vulnerable, create a new IScanIssue and return the List<IScanIssue>

        pass

    def consolidateDuplicateIssues(self, isb, isa):
        # TODO
        pass

class ELJ(IScanIssue):
    # TODO
    pass
