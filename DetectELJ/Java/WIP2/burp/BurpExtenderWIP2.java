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
        byte[] withPayload = isip.buildRequest("${1336+1}".getBytes());
        //2 - Send the HTTP request
        IHttpRequestResponse newReqRes = callbacks.makeHttpRequest(ihrr.getHttpService(), withPayload);
        //3 - Diff original and new responses (tip: analyzeResponseVariations and getVariantAttributes)
        IResponseVariations variation = helpers.analyzeResponseVariations(ihrr.getResponse(), newReqRes.getResponse());
        List<String> pageChanges = variation.getVariantAttributes();
        //4 - Based on page changes, determine whether the page is vulnerable or not
        boolean length = false;
        boolean bodyContent = false;
        boolean match = false;

        for (String change : pageChanges) {
            if (change.equals("content_length")) length = true;
            if (change.equals("whole_body_content")) bodyContent = true;
        }

        if (helpers.bytesToString(newReqRes.getResponse()).contains("1337")) match = true;
        //5 - If vulnerable, create a new IScanIssue and return the List<IScanIssue>
        if (length && bodyContent && match) {
            //TODO
        } else {
            return null;
        }
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue isb, IScanIssue isa) {
        //TODO
        //If it is the same URL and same type of response, consider as the same security issue, otherwise different
    }

    class ELJ implements IScanIssue {

        private final IHttpRequestResponse reqres;

        public ELJ(IHttpRequestResponse reqres) {
            this.reqres = reqres;
        }

        @Override
        public String getHost() {
            return reqres.getHost();
        }

        @Override
        public int getPort() {
            return reqres.getPort();
        }

        @Override
        public String getProtocol() {
            return reqres.getProtocol();
        }

        @Override
        public URL getUrl() {
            return reqres.getUrl();
        }

        @Override
        public String getIssueName() {
            return "Expression Language (EL) Injection Detected";
        }

        @Override
        public int getIssueType() {
            return 0x08000000; //See http://portswigger.net/burp/help/scanner_issuetypes.html
        }

        @Override
        public String getSeverity() {
            return "High"; // "High", "Medium", "Low", "Information" or "False positive"
        }

        @Override
        public String getConfidence() {
            return "Firm"; //"Certain", "Firm" or "Tentative"
        }

        @Override
        public String getIssueBackground() {
            return "Expression Language injections occur when input data is evaluated "
                    + "by an expression language interpreter. An attacker can read server-side "
                    + "data, such as the content of server-side variables, and some other inner "
                    + "configuration details.";
        }

        @Override
        public String getRemediationBackground() {
            return "Apply input validation best practices, and reject ${, #{ and other variations.";
        }

        @Override
        public String getIssueDetail() {
            return "Burp Scanner has identified an Expression Language injection in:<b>"
                    + reqres.getUrl().toString() + "</b><br><br>";
        }

        @Override
        public String getRemediationDetail() {
            return null;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            //Let's highlight the specific string in the response that triggered the issue
            
            //TODO
        }

        @Override
        public IHttpService getHttpService() {
            return reqres.getHttpService();
        }
    }
}
