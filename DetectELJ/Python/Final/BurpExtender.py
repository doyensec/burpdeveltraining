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
        withPayload = isip.buildRequest(StringUtil.toBytes('${1336+1}'))
        newReqRes = self.callbacks.makeHttpRequest(ihrr.getHttpService(), withPayload)

        variation = self.helpers.analyzeResponseVariations(ihrr.getResponse(), newReqRes.getResponse())
        pageChanges = variation.getVariantAttributes()

        length = False
        bodyContent = False
        match = False

        for change in pageChanges:
            if change == 'content_length':
                length = True
            if change == 'whole_body_content':
                bodyContent = True
        
        match = '1337' in self.helpers.bytesToString(newReqRes.getResponse())
        
        if length and bodyContent and match:
            issues = ArrayList()
            issues.add(ELJ(newReqRes, self.callbacks, self.helpers))
            return issues
        else:
            return None

    def consolidateDuplicateIssues(self, isb, isa):
        if Arrays.equals(isb.getHttpMessages()[0].getResponse(), isa.getHttpMessages()[0].getResponse()):
            return -1
        else:
            return 0


class ELJ(IScanIssue):

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
        strRes = self.helpers.bytesToString(self.reqres.getResponse())
        marks = [None, None]
        # XXX: shim for python objects
        marks[0] = strRes.index('1337')
        marks[1] = marks[0] + 4
        marks = array(marks, 'i')
        marksList = ArrayList()
        marksList.add(marks)
        reqresMark = self.callbacks.applyMarkers(self.reqres, None, marksList)
        rra = [reqresMark]
        return rra

    def getHttpService(self):
        return self.reqres.getHttpService()
