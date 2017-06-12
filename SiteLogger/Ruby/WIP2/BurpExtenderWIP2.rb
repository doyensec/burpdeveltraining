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
    callbacks.addSuiteTab(SiteLoggerTab.new(callbacks, helpers))
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

  def getTabCaption()
    return "SiteLogger"
  end

  def getUiComponent()
    panel = SiteLoggerPanel.new(callbacks, helpers)
    callbacks.customizeUiComponent(panel.this)
    return panel.this
  end
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

  def initComponents()
    # 4 - Define here the AWT/Swing UI which should contain three text fields (mongohost, mongoport, website) and save button

    # TODO

    pass
  end

  def logButtonActionPerformed(evt) #GEN-FIRST:event_logButtonActionPerformed

    stdout = PrintWriter.new(callbacks.getStdout(), true)
    stderr = PrintWriter.new(callbacks.getStderr(), true)

    begin
      # 5 - Connect to the database and create the collections
      mongo = MongoClient.new(@mongohost.getText().to_s, @mongoport.getText().to_i)
      db = mongo.getDB("sitelogger")
      siteUrl = URL.new(@website.getText())
      tableSite = db.getCollection(siteUrl.getHost().gsub(".", "_") + "_site")
      tableVuln = db.getCollection(siteUrl.getHost().gsub(".", "_") + "_vuln")

      # 6 - Retrieve SiteMap HTTP Requests and Responses and save to the database
      allReqRes = callbacks.getSiteMap(@website.getText())
      for rc in 0...allReqRes.length
        # 7 - Save each HTTP request/response to the database
        document = BasicDBObject.new()
        document.put("host", allReqRes[rc].getHost())
        document.put("port", allReqRes[rc].getPort().to_i32)
        document.put("protocol", allReqRes[rc].getProtocol())
        document.put("URL", allReqRes[rc].getUrl().toString())
        document.put("status_code", allReqRes[rc].getStatusCode())
        if (allReqRes[rc].getRequest() != nil)
          document.put("request", helpers.base64Encode(allReqRes[rc].getRequest()))
        end
        if (allReqRes[rc].getResponse() != nil)
          document.put("response", helpers.base64Encode(allReqRes[rc].getResponse()))
        end
        tableSite.insert(document)
      end

      # 8 - Retrieve Scan findings and save to the database
      allVulns = callbacks.getScanIssues(@website.getText())
      for vc in 0...allVulns.length
        # 9 - Save each vulnerability report to the database, including HTTP request/response
        document = BasicDBObject.new()
        document.put("type", allVulns[vc].getIssueType())
        document.put("name", allVulns[vc].getIssueName())
        document.put("detail", allVulns[vc].getIssueDetail())
        document.put("severity", allVulns[vc].getSeverity())
        document.put("confidence", allVulns[vc].getConfidence())
        document.put("host", allVulns[vc].getHost())
        document.put("port", allVulns[vc].getPort().to_i32)
        document.put("protocol", allVulns[vc].getProtocol())
        document.put("URL", allVulns[vc].getUrl().toString())
        if (allVulns[vc].getHttpMessages().length > 1)
          if (allVulns[vc].getHttpMessages()[0].getRequest() != nil)
            document.put("request", helpers.base64Encode(allVulns[vc].getHttpMessages()[0].getRequest()))
          end
          if (allVulns[vc].getHttpMessages()[0].getResponse() != nil)
            document.put("response", helpers.base64Encode(allVulns[vc].getHttpMessages()[0].getResponse()))
          end
        end
        tableVuln.insert(document)
      end

      callbacks.issueAlert("Data Saved!")

    rescue UnknownHostException => ex
      stderr.println("Mongo DB Connection Error:" + ex.toString())
    rescue MalformedURLException => ex
      stderr.println("Malformed URL:" + ex.toString())
    end
  end #GEN-LAST:event_@logButtonActionPerformed
end
