/*
 * HelloBurp - A simple extension to show alerts, stdout/stderr and custom UI
 *
 * Copyright (c) 2017 Doyensec LLC. Made with love by Luca Carettoni.
 */

package burp;

import java.awt.Button;
import java.awt.Color;
import java.awt.Component;
import java.awt.Panel;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Hello Burp!");

        // 1 - Use issueAlert to trigger an alert
        callbacks.issueAlert("Once again, Hello Burp!");  //Alerts tab

        // 2 - Use getStdout and getStderr to instantiate two PrintWriter instances
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout.println("Hello Burp in StdOut!"); //StdOut (either terminal, file or Burp's UI)
        stderr.println("Hello Burp in StdErr!"); //StdErr (either terminal, file or Burp's UI)

        // 3 - Instantiate a custom ITab implementation and add the tab to Burp (tip: use addSuiteTab)
        callbacks.addSuiteTab(new HelloBurpTab()); //Custom tab with custom UI components
    }

    private class HelloBurpTab implements ITab {

        @Override
        public String getTabCaption() {
            //TODO
        }

        @Override
        public Component getUiComponent() {
            //TODO
        }
    }
}
