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
    # 1 - Convert byte[] response to String

    # 2 - Check if the page includes a 'integrity="(sha256|sha384|sha512) ...' attribute (tip: use RegExp Pattern.compile and matcher)

    # 3 - Based on the match and page type, determine whether the page is vulnerable or not

    # 4 - If vulnerable, create a new IScanIssue and return the List<IScanIssue>

  end

  def doActiveScan(ihrr, isip)
    return nil #Passive scanner check only
  end

  def consolidateDuplicateIssues(isb, isa)
    return -1
  end
end

class SRI
  # TODO
end
