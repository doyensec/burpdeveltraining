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
    # 2 - Use getStdout and getStderr to instantiate two PrintWriter instances
    # 3 - Instantiate a custom ITab implementation and add the tab to Burp (tip: use addSuiteTab)
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
