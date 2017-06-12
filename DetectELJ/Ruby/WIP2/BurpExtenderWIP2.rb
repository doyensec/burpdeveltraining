#
# DetectELJ - Active scanner extension to detect Expression Language Injection vulnerabilities
#
# Copyright (c) 2017 Doyensec LLC. Made with love by Andrea Brancaleoni.
#
require 'java'

java_import 'burp.IBurpExtender'
java_import 'burp.IScannerCheck'
java_import 'burp.IScanIssue'
java_import 'burp.IHttpRequestResponse'
java_import 'java.io.PrintWriter'
java_import 'java.net.URL'
java_import 'java.util.ArrayList'
java_import 'java.util.Arrays'
java_import 'java.util.List'

class BurpExtender
  include IBurpExtender
  include IScannerCheck

  attr_reader :helpers
  attr_reader :callbacks

  def registerExtenderCallbacks(callbacks)
    @callbacks = callbacks
    @helpers = callbacks.getHelpers()
    callbacks.setExtensionName('DetectELJ')

    callbacks.issueAlert('DetectELJ Active Scanner check enabled')

    stdout = PrintWriter.new(callbacks.getStdout(), true)
    stderr = PrintWriter.new(callbacks.getStderr(), true)

    callbacks.registerScannerCheck(self)
  end

  def print(e)
    @callbacks.issueAlert(e.to_s)
  end

  def doPassiveScan(ihrr)
    return nil # Active scanner check only
  end


  def doActiveScan(ihrr, isip)
    # 1 - Create a new request with our custom payload (tip: buildRequest)
    withPayload = isip.buildRequest('${1336+1}'.to_java_bytes())
    # 2 - Send the HTTP request
    newReqRes = callbacks.makeHttpRequest(ihrr.getHttpService(), withPayload)
    # 3 - Diff original and new responses (tip: analyzeResponseVariations and getVariantAttributes)
    variation = helpers.analyzeResponseVariations(ihrr.getResponse(), newReqRes.getResponse())
    pageChanges = variation.getVariantAttributes()
    # 4 - Based on page changes, determine whether the page is vulnerable or not
    length = false
    bodyContent = false
    match = false

    pageChanges.each do |change|
      length = true if change == 'content_length'
      bodyContent = true if change == 'whole_body_content'
    end

    # XXX: ruby string contains shim
    match = helpers.bytesToString(newReqRes.getResponse())['1337']
    # 5 - If vulnerable, create a new IScanIssue and return the List<IScanIssue>
    if (length && bodyContent && match)
      # TODO
    else
      return nil
    end
  end


  def consolidateDuplicateIssues(isb, isa)
    # TODO
  end

end

class ELJ
  include IScanIssue
  attr_reader :helpers
  attr_reader :reqres
  attr_reader :callbacks

  def initialize(reqres, callbacks, helpers)
    @reqres = reqres
    @callbacks = callbacks
    @helpers = helpers
  end


  def getHost()
    return reqres.getHost()
  end


  def getPort()
    return reqres.getPort()
  end


  def getProtocol()
    return reqres.getProtocol()
  end


  def getUrl()
    return reqres.getUrl()
  end


  def getIssueName()
    return 'Expression Language (EL) Injection Detected'
  end


  def getIssueType()
    return 0x08000000 # See http://portswigger.net/burp/help/scanner_issuetypes.html
  end


  def getSeverity()
    return 'High' #  'High', 'Medium', 'Low', 'Information' or 'False positive'
  end


  def getConfidence()
    return 'Firm' # 'Certain', 'Firm' or 'Tentative'
  end


  def getIssueBackground()
    return 'Expression Language injections occur when input data is evaluated ' +
    'by an expression language interpreter. An attacker can read server-side ' +
    'data, such as the content of server-side variables, and some other inner ' +
    'configuration details.'
  end


  def getRemediationBackground()
    return 'Apply input validation best practices, and reject $, # and other variations.'
  end


  def getIssueDetail()
    return 'Burp Scanner has identified an Expression Language injection in:<b>' +
            reqres.getUrl().toString() + '</b><br><br>'
  end


  def getRemediationDetail()
    return nil
  end


  def getHttpMessages()
    # Let's highlight the specific string in the response that triggered the issue
    # TODO
  end


  def getHttpService()
    return reqres.getHttpService()
  end
end
