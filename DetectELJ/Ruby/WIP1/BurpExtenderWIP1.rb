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

    # 2 - Send the HTTP request

    # 3 - Diff original and new responses (tip: analyzeResponseVariations and getVariantAttributes)

    # 4 - Based on page changes, determine whether the page is vulnerable or not

    # 5 - If vulnerable, create a new IScanIssue and return the List<IScanIssue>
  end


  def consolidateDuplicateIssues(isb, isa)
    # TODO
  end

end

class ELJ
  # TODO
end
