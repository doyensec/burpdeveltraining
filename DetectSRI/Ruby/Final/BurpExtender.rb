#
#  DetectSRI - A passive scanner extension to detect missing Subresource Integrity (SRI) within a page
#
#  Copyright (c) 2017 Doyensec LLC. Made with love by Andrea Brancaleoni.
#
require 'java'
java_import 'burp.IBurpExtender'
java_import 'burp.IScannerCheck'
java_import 'burp.IScanIssue'
java_import 'burp.IHttpRequestResponse'
java_import 'java.io.PrintWriter'
java_import 'java.net.URL'
java_import 'java.util.ArrayList'
java_import 'java.util.List'
java_import 'java.util.regex.Matcher'
java_import 'java.util.regex.Pattern'

class BurpExtender
  include IBurpExtender
  include IScannerCheck

  def registerExtenderCallbacks(callbacks)
    @callbacks = callbacks
    @helpers = callbacks.getHelpers()
    callbacks.setExtensionName("DetectSRI")

    callbacks.issueAlert("DetectSRI Passive Scanner check enabled")

    stdout = PrintWriter.new(callbacks.getStdout(), true)
    @stderr = PrintWriter.new(callbacks.getStderr(), true)

    callbacks.registerScannerCheck(self)
  end

  def doPassiveScan(ihrr)
    response = @helpers.bytesToString(ihrr.getResponse)
    p = Pattern.compile(".*integrity=\"(sha256|sha384|sha512)-[A-Za-z0-9+/=]+.*", Pattern::DOTALL)
    m = p.matcher(response)
    #Check match for html pages only
    # XXX: java strings were casted to ruby strings and therefore the contains
    #      method is missing. We could use ruby methods instead. String[] methods
    #      in ruby returns the index of the match or nil, then it is sufficient
    #      to emulate the .contains Java String method.
    if (response["<html"] && !m.matches())
      #The page does NOT contain any SRI attribute
      issues = ArrayList.new
      issues.add(SRI.new(ihrr))
      return issues
    end
    return nil
  end

  def doActiveScan(ihrr, isip)
    return nil #Passive scanner check only
  end

  def consolidateDuplicateIssues(isb, isa)
    return -1
  end
end

class SRI
  include IScanIssue

  def initialize(reqres)
    @reqres = reqres
  end

  def getHost()
    return @reqres.getHost()
  end

  def getPort()
    return @reqres.getPort()
  end

  def getProtocol()
    return @reqres.getProtocol()
  end

  def getUrl()
    return @reqres.getUrl()
  end

  def getIssueName()
    return "Subresource Integrity (SRI) Missing"
  end

  def getIssueType()
    return 0x08000000 #See http:#portswigger.net/burp/help/scanner_issuetypes.html
  end

  def getSeverity()
    return "Information" # "High", "Medium", "Low", "Information" or "False positive"
  end

  def getConfidence()
    return "Certain" #"Certain", "Firm" or "Tentative"
  end

  def getIssueBackground()
    return "Subresource Integrity (SRI) is a security feature that enables " +
      "browsers to verify that files they fetch (for example, from a CDN) " +
      "are delivered without unexpected manipulation. It works by allowing" +
      "you to provide a cryptographic hash that a fetched file must match."
  end

  def getRemediationBackground()
    return "this is an <b>informational</b> finding only.<br>"
  end

  def getIssueDetail()
    return "Burp Scanner has not identified Subresource Integrity (SRI) attributes in the following page: <b>" +
      @reqres.getUrl().toString() + "</b><br><br>"
  end

  def getRemediationDetail()
    return nil
  end

  def getHttpMessages()
    # XXX: it is possible to cast a ruby array to a native Java array with the
    #      to_java method
    return [@reqres].to_java(IHttpRequestResponse)
  end

  def getHttpService()
    return @reqres.getHttpService()
  end
end
