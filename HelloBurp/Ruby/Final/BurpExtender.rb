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

    callbacks.issueAlert('Once again, Hello Burp!') # Alerts tab

    stdout = PrintWriter.new(callbacks.getStdout, true)
    stderr = PrintWriter.new(callbacks.getStderr, true)

    stdout.println('Hello Burp in StdOut!') # StdOut (either terminal, file or Burp's UI)
    stderr.println('Hello Burp in StdErr!') # StdErr (either terminal, file or Burp's UI)

    # XXX: It is not possible to use the "friendly" accessors in ruby
    # XXX: it is therefore necessary to pass the callback object during HelloBurpTab construction
    callbacks.addSuiteTab(HelloBurpTab.new(@callbacks)) # Custom tab with custom UI components
  end
end

class HelloBurpTab
  include ITab
  def initialize(callbacks)
    @callbacks = callbacks
  end

  def getTabCaption
    'Hello Burp Tab!'
  end

  def getUiComponent
    panel = Panel.new
    panel.setBackground(Color.gray)
    button = Button.new('Hello Burp Button!')
    panel.add(button)
    @callbacks.customizeUiComponent(panel) # customize UI components in line with Burp's UI style
    panel
  end
end
