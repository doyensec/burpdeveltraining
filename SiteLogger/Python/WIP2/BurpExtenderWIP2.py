#
# SiteLogger - Log sitemap and findings to database
#
# Copyright (c) 2017 Doyensec LLC. Made with love by Andrea Brancaleoni.
#

from java.awt import Component

from burp import IBurpExtenderCallbacks, IExtensionHelpers, IHttpRequestResponse
from burp import IScanIssue, ITab, IBurpExtender
from com.mongodb import BasicDBObject, DB, DBCollection, MongoClient

from java.io import PrintWriter
from java.net import MalformedURLException, URL, UnknownHostException

from javax.swing import (BoxLayout, ImageIcon, JButton, JFrame, JPanel,
        JPasswordField, JLabel, JTextArea, JTextField, JScrollPane,
        SwingConstants, WindowConstants, GroupLayout)
import javax
from java.lang import Short, Integer


# Original code from src/burp/BurpExtender.java class
class BurpExtender(IBurpExtender):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SiteLogger")

        # 1 - Add a custom tab to Burp (using addSuiteTab)
        # Please use a separate file named 'SiteLoggerTab' within the package 'com.doyensec.sitelogger'
        callbacks.addSuiteTab(SiteLoggerTab(callbacks, helpers))


# Original code from src/com/doyensec/SiteLoggerTab.java class
class SiteLoggerTab(ITab):

    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers

    def getTabCaption(self):
        return "SiteLogger"

    def getUiComponent(self):
        panel = SiteLoggerPanel(self.callbacks, self.helpers)
        self.callbacks.customizeUiComponent(panel.this)
        return panel.this


# Original code from src/com/doyensec/SiteLoggerPanel.java class
# XXX: inheriting from Java classes is very tricky. It is preferable to use
#      the decorator pattern instead.
class SiteLoggerPanel:

    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self.this = JPanel()
        self.initComponents()

    def initComponents(self):

        # 4 - Define here the AWT/Swing UI which should contain three text fields (mongohost, mongoport, website) and save button

        # TODO

        pass

    # Button Event Click - Our code goes here!
    def logButtonActionPerformed(self, evt):
        stdout = PrintWriter(self.callbacks.getStdout(), True)
        stderr = PrintWriter(self.callbacks.getStderr(), True)

        try:
            # 5 - Connect to the database and create the collections
            mongo = MongoClient(self.mongohost.getText(), Integer.parseInt(self.mongoport.getText()))
            db = mongo.getDB("sitelogger")
            siteUrl = URL(self.website.getText())
            tableSite = db.getCollection(siteUrl.getHost().replace(".", "_") + "_site")
            tableVuln = db.getCollection(siteUrl.getHost().replace(".", "_") + "_vuln")

            # 6 - Retrieve SiteMap HTTP Requests and Responses and save to the database
            allReqRes = self.callbacks.getSiteMap(self.website.getText())
            for rc in xrange(0, len(allReqRes)):
                # 7 - Save each HTTP request/response to the database
                document = BasicDBObject()
                document.put("host", allReqRes[rc].getHost())
                document.put("port", allReqRes[rc].getPort())
                document.put("protocol", allReqRes[rc].getProtocol())
                document.put("URL", allReqRes[rc].getUrl().toString())
                document.put("status_code", allReqRes[rc].getStatusCode())
                if (allReqRes[rc].getRequest() != None):
                    document.put("request", self.helpers.base64Encode(allReqRes[rc].getRequest()))

                if (allReqRes[rc].getResponse() != None):
                    document.put("response", self.helpers.base64Encode(allReqRes[rc].getResponse()))

                tableSite.insert(document)


            # 8 - Retrieve Scan findings and save to the database
            allVulns = self.callbacks.getScanIssues(self.website.getText())
            for vc in xrange(0, len(allVulns)):
                # 9 - Save each vulnerability report to the database, including HTTP request/response
                document = BasicDBObject()
                document.put("type", allVulns[vc].getIssueType())
                document.put("name", allVulns[vc].getIssueName())
                document.put("detail", allVulns[vc].getIssueDetail())
                document.put("severity", allVulns[vc].getSeverity())
                document.put("confidence", allVulns[vc].getConfidence())
                document.put("host", allVulns[vc].getHost())
                document.put("port", allVulns[vc].getPort())
                document.put("protocol", allVulns[vc].getProtocol())
                document.put("URL", allVulns[vc].getUrl().toString())
                if (len(allVulns[vc].getHttpMessages()) > 1):
                    if (allVulns[vc].getHttpMessages()[0].getRequest() != None):
                        document.put("request", self.helpers.base64Encode(allVulns[vc].getHttpMessages()[0].getRequest()))

                    if (allVulns[vc].getHttpMessages()[0].getResponse() != None):
                        document.put("response", self.helpers.base64Encode(allVulns[vc].getHttpMessages()[0].getResponse()))


                tableVuln.insert(document)


            self.callbacks.issueAlert("Data Saved!")

        except UnknownHostException as ex:
            stderr.println("Mongo DB Connection Error:" + ex.toString())
        except MalformedURLException as ex:
            stderr.println("Malformed URL:" + ex.toString())
