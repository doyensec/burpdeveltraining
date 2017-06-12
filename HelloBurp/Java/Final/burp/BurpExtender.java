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

        callbacks.issueAlert("Once again, Hello Burp!");  //Alerts tab

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout.println("Hello Burp in StdOut!"); //StdOut (either terminal, file or Burp's UI)
        stderr.println("Hello Burp in StdErr!"); //StdErr (either terminal, file or Burp's UI)

        callbacks.addSuiteTab(new HelloBurpTab()); //Custom tab with custom UI components
    }

    private class HelloBurpTab implements ITab {

        @Override
        public String getTabCaption() {
            return "Hello Burp Tab!";
        }

        @Override
        public Component getUiComponent() {
            Panel panel = new Panel();
            panel.setBackground(Color.gray);
            Button button = new Button("Hello Burp Button!");
            panel.add(button);
            callbacks.customizeUiComponent(panel); //customize UI components in line with Burp's UI style
            return panel;
        }
    }
}
