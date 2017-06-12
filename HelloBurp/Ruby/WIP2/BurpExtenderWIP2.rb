#
# HelloBurp - A simple extension to show alerts, stdout/stderr and custom UI
#
# Copyright (c) 2017 Doyensec LLC. Made with love by Andrea Brancaleoni.
#

require 'java'
java_import 'burp.IBurpExtender'
java_import 'burp.ITab'
java_import 'java.awt.Button'
java_import 'java.awt.Color'
java_import 'java.awt.Component'
java_import 'java.awt.Panel'
java_import 'java.io.PrintWriter'

class BurpExtender
  include IBurpExtender

  def registerExtenderCallbacks(callbacks)
    @callbacks = callbacks
    @helpers = callbacks.getHelpers()
    callbacks.setExtensionName('Hello Burp!')

    # 1 - Use issueAlert to trigger an alert
    callbacks.issueAlert('Once again, Hello Burp!') # Alerts tab

    # 2 - Use getStdout and getStderr to instantiate two PrintWriter instances
    stdout = PrintWriter.new(callbacks.getStdout, true)
    stderr = PrintWriter.new(callbacks.getStderr, true)

    stdout.println('Hello Burp in StdOut!') # StdOut (either terminal, file or Burp's UI)
    stderr.println('Hello Burp in StdErr!') # StdErr (either terminal, file or Burp's UI)

    # XXX: It is not possible to use the "friendly" accessors in ruby
    # XXX: it is therefore necessary to pass the callback object during HelloBurpTab construction
    # 3 - Instantiate a custom ITab implementation and add the tab to Burp (tip: use addSuiteTab)
    callbacks.addSuiteTab(HelloBurpTab.new(@callbacks)) # Custom tab with custom UI components
  end
end

class HelloBurpTab
  include ITab
  def initialize(callbacks)
    @callbacks = callbacks
  end

  def getTabCaption
    # TODO
  end

  def getUiComponent
    # TODO
  end
end
