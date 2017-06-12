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


# Original code from src/com/doyensec/SiteLoggerTab.java class
class SiteLoggerTab(ITab):

    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers

    # 2 - Simply implement all ITab's methods (getTabCaption and getUiComponent)

    # 3 - In getUiComponent, instantiate a new Jpanel created using standard Java AWT/Swing GUI Editors


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
        pass

    def logButtonActionPerformed(self, evt):
        # 5 - Connect to the database and create two new collections for storing sitemap and vulns

        # 6 - Retrieve the SiteMap content (using Burp's getSiteMap)

        # 7 - Save each HTTP request/response to the database

        # 8 - Retrieve all scanner findings (using Burp's getScanIssues)

        # 9 - Save each vulnerability report to the database, including HTTP request/response
