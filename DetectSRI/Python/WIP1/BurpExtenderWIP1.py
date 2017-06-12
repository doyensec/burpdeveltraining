#
#  DetectSRI - A passive scanner extension to detect missing Subresource Integrity (SRI) within a page
#
#  Copyright (c) 2017 Doyensec LLC. Made with love by Andrea Brancaleoni.
#
from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern


class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("DetectSRI")

        callbacks.issueAlert("DetectSRI Passive Scanner check enabled")

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, ihrr):
        # 1 - Convert byte[] response to String

        # 2 - Check if the page includes a 'integrity="(sha256|sha384|sha512) ...' attribute (tip: use RegExp Pattern.compile and matcher)

        # 3 - Based on the match and page type, determine whether the page is vulnerable or not

        # 4 - If vulnerable, create a new IScanIssue and return the List<IScanIssue>

    def doActiveScan(self, ihrr, isip):
        return None  # Passive scanner check only

    def consolidateDuplicateIssues(self, isb, isa):
        return -1


class SRI(IScanIssue):
    # TODO
    pass
