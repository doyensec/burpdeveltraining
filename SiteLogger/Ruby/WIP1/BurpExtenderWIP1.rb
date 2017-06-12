#
# SiteLogger - Log sitemap and findings to database
#
# Copyright (c) 2017 Doyensec LLC. Made with love by Andrea Brancaleoni.
#

require 'java'
java_import 'burp.IBurpExtender'
java_import 'burp.IBurpExtenderCallbacks'
java_import 'burp.IExtensionHelpers'
java_import 'burp.ITab'
java_import 'java.awt.Component'

java_import 'java.awt.Button'
java_import 'java.awt.Color'
java_import 'java.awt.Panel'

java_import 'javax.swing.JPanel'
java_import 'burp.IBurpExtenderCallbacks'
java_import 'burp.IExtensionHelpers'
java_import 'burp.IHttpRequestResponse'
java_import 'burp.IScanIssue'
java_import 'com.mongodb.BasicDBObject'
java_import 'com.mongodb.DB'
java_import 'com.mongodb.DBCollection'
java_import 'com.mongodb.MongoClient'
java_import 'java.io.PrintWriter'
java_import 'java.net.MalformedURLException'
java_import 'java.net.URL'
java_import 'java.net.UnknownHostException'
java_import 'java.lang.Short'

# Original code from src/burp/BurpExtender.java class
class BurpExtender
  include IBurpExtender

  def registerExtenderCallbacks(callbacks)
    @callbacks = callbacks
    helpers = callbacks.getHelpers()
    callbacks.setExtensionName("SiteLogger")

    # 1 - Add a custom tab to Burp (using addSuiteTab)
    # Please use a separate file named 'SiteLoggerTab' within the package 'com.doyensec.sitelogger'
  end
end

# Original code from src/com/doyensec/SiteLoggerTab.java class
class SiteLoggerTab
  include ITab

  attr_reader :callbacks
  attr_reader :helpers

  def initialize(callbacks, helpers)
    @callbacks = callbacks
    @helpers = helpers
  end

  # 2 - Simply implement all ITab's methods (getTabCaption and getUiComponent)

  # 3 - In getUiComponent, instantiate a new Jpanel created using standard Java AWT/Swing GUI Editors
end

# Original code from src/com/doyensec/SiteLoggerPanel.java class
# XXX: inheriting from Java classes is very tricky. It is preferable to use
#      the decorator pattern instead.
class SiteLoggerPanel
  attr_accessor :callbacks
  attr_accessor :helpers
  attr_accessor :this

  def initialize(callbacks, helpers)
    @this = JPanel.new
    @callbacks = callbacks
    @helpers = helpers
    initComponents()
  end

  def initComponents
    # 4 - Define here the AWT/Swing UI which should contain three text fields (mongohost, mongoport, website) and save button

    # TODO
  end

  def logButtonActionPerformed(evt)
    # 5 - Connect to the database and create two new collections for storing sitemap and vulns

    # 6 - Retrieve the SiteMap content (using Burp's getSiteMap)

    # 7 - Save each HTTP request/response to the database

    # 8 - Retrieve all scanner findings (using Burp's getScanIssues)

    # 9 - Save each vulnerability report to the database, including HTTP request/response
  end
end
