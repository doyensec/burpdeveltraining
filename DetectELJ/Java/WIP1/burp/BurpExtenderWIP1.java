/*
 * DetectELJ - Active scanner extension to detect Expression Language Injection vulnerabilities
 *
 * Copyright (c) 2017 Doyensec LLC. Made with love by Luca Carettoni.
 */
package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("DetectELJ");

        callbacks.issueAlert("DetectELJ Active Scanner check enabled");

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.registerScannerCheck(this);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse ihrr) {
        return null; //Active scanner check only
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse ihrr, IScannerInsertionPoint isip) {

        //1 - Create a new request with our custom payload (tip: buildRequest)

        //2 - Send the HTTP request

        //3 - Diff original and new responses (tip: analyzeResponseVariations and getVariantAttributes)

        //4 - Based on page changes, determine whether the page is vulnerable or not

        //5 - If vulnerable, create a new IScanIssue and return the List<IScanIssue>

    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue isb, IScanIssue isa) {
        //TODO
    }

    class ELJ implements IScanIssue {
       //TODO 
    }
}
