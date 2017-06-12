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
        withPayload = isip.buildRequest(StringUtil.toBytes('${1336+1}'))
        # 2 - Send the HTTP request
        newReqRes = self.callbacks.makeHttpRequest(ihrr.getHttpService(), withPayload)
        # 3 - Diff original and new responses (tip: analyzeResponseVariations and getVariantAttributes)
        variation = self.helpers.analyzeResponseVariations(ihrr.getResponse(), newReqRes.getResponse())
        pageChanges = variation.getVariantAttributes()
        # 4 - Based on page changes, determine whether the page is vulnerable or not
        length = False
        bodyContent = False
        match = False

        for change in pageChanges:
            if change == 'content_length':
                length = True
            if change == 'whole_body_content':
                bodyContent = True

        match = '1337' in self.helpers.bytesToString(newReqRes.getResponse())
        # 5 - If vulnerable, create a new IScanIssue and return the List<IScanIssue>
        if length and bodyContent and match:
            pass
            # TODO
        else:
            return None

    def consolidateDuplicateIssues(self, isb, isa):
        # TODO
        # If it is the same URL and same type of response, consider as the same security issue, otherwise different
        pass


class ELJ(IScanIssue):
    # TODO
    pass

    def __init__(self, reqres, callbacks, helpers):
        self.reqres = reqres
        self.callbacks = callbacks
        self.helpers = helpers

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return 'Expression Language (EL) Injection Detected'

    def getIssueType(self):
        return 0x08000000  # See http://portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return 'High'  # 'High', 'Medium', 'Low', 'Information' or 'False positive'

    def getConfidence(self):
        return 'Firm'  # 'Certain', 'Firm' or 'Tentative'

    def getIssueBackground(self):
        return str('Expression Language injections occur when input data is evaluated '
                   'by an expression language interpreter. An attacker can read server-side '
                   'data, such as the content of server-side variables, and some other inner '
                   'configuration details.')

    def getRemediationBackground(self):
        return 'Apply input validation best practices, and reject $, # and other variations.'

    def getIssueDetail(self):
        return str('Burp Scanner has identified an Expression Language injection in:<b>'
                   '%s</b><br><br>' % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        # Let's highlight the specific string in the response that triggered the issue

        # TODO
        pass

    def getHttpService(self):
        return self.reqres.getHttpService()
