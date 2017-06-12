/*
 * DetectSRI - A passive scanner extension to detect missing Subresource Integrity (SRI) within a page
 *
 * Copyright (c) 2017 Doyensec LLC. Made with love by Luca Carettoni.
 */
package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("DetectSRI");

        callbacks.issueAlert("DetectSRI Passive Scanner check enabled");

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.registerScannerCheck(this);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse ihrr) {

        // 1 - Convert byte[] response to String

        // 2 - Check if the page includes a 'integrity="(sha256|sha384|sha512) ...' attribute (tip: use RegExp Pattern.compile and matcher)

        // 3 - Based on the match and page type, determine whether the page is vulnerable or not

        //4 - If vulnerable, create a new IScanIssue and return the List<IScanIssue>

    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse ihrr, IScannerInsertionPoint isip) {
        return null; //Passive scanner check only
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue isb, IScanIssue isa) {
        return -1;
    }

    class SRI implements IScanIssue {
        //TODO
    }    
}
