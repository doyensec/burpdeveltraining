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
        response = self.helpers.bytesToString(ihrr.getResponse())
        # 2 - Check if the page includes a 'integrity="(sha256|sha384|sha512) ...' attribute (tip: use RegExp Pattern.compile and matcher)
        p = Pattern.compile('.*integrity=\"(sha256|sha384|sha512)-[A-Za-z0-9+/=]+.*', Pattern.DOTALL)
        m = p.matcher(response)
        # 3 - Based on the match and page type, determine whether the page is vulnerable or not
        # Check match for html pages only
        # XXX: Java string are automatically boxed into python unicode objects,
        #      therefore is not possible to use the contains method anymore.
        #      In order to check if a substring is present in a string, we need
        #      to use the in operator.
        if "<html" in response and not m.matches():
            # 4 - If vulnerable, create a new IScanIssue and return the List<IScanIssue>
            # TODO

        return None

    def doActiveScan(self, ihrr, isip):
        return None  # Passive scanner check only

    def consolidateDuplicateIssues(self, isb, isa):
        return -1


class SRI(IScanIssue):
    def __init__(self, reqres):
        self.reqres = reqres

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "Subresource Integrity (SRI) Missing"

    def getIssueType(self):
        return 0x08000000  # See http:#portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return "Information"  # "High", "Medium", "Low", "Information" or "False positive"

    def getConfidence(self):
        return "Certain"  # "Certain", "Firm" or "Tentative"

    def getIssueBackground(self):
        return str("Subresource Integrity (SRI) is a security feature that enables "
                      "browsers to verify that files they fetch (for example, from a CDN) "
                      "are delivered without unexpected manipulation. It works by allowing"
                      "you to provide a cryptographic hash that a fetched file must match.")

    def getRemediationBackground(self):
        return "this is an <b>informational</b> finding only.<br>"

    def getIssueDetail(self):
        return str("Burp Scanner has not identified Subresource Integrity (SRI) attributes in the following page: <b>"
                      "%s</b><br><br>" % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        # XXX: Jython arrays are automatically boxed in Java arrays when the
        #      function returns
        rra = [self.reqres]
        return rra

    def getHttpService(self):
        return self.reqres.getHttpService()
