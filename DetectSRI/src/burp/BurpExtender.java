/*
 * DetectSRI - A passive scanner extension to detect the use of Subresource Integrity (SRI) within a page
 *
 * Copyright (c) 2017 Luca Carettoni - Doyensec LLC.
 */
package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
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

        String response = new String(ihrr.getResponse(), StandardCharsets.UTF_8);
        Pattern p = Pattern.compile(".*integrity=\"(sha256|sha384|sha512)-[A-Za-z0-9+/=]+.*", Pattern.DOTALL);
        Matcher m = p.matcher(response);
        if (m.matches()) {
            //The page contains a SRI tag
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new SRI(ihrr));
            return issues;
        }
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse ihrr, IScannerInsertionPoint isip) {
        return null; //Passive scanner check only
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue isb, IScanIssue isa) {
        if (isb.getUrl().equals(isa.getUrl())) {
            return -1;
        } else {
            return 0;
        }
    }

    class SRI implements IScanIssue {

        private IHttpRequestResponse reqres;

        public SRI(IHttpRequestResponse reqres) {
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
            return "Subresource Integrity (SRI) Detected";
        }

        @Override
        public int getIssueType() {
            return 0x08000000; //See http://portswigger.net/burp/help/scanner_issuetypes.html
        }

        @Override
        public String getSeverity() {
            return "Information"; // "High", "Medium", "Low", "Information" or "False positive"
        }

        @Override
        public String getConfidence() {
            return "Certain"; //"Certain", "Firm" or "Tentative"
        }

        @Override
        public String getIssueBackground() {
            return "Subresource Integrity (SRI) is a security feature that enables "
                    + "browsers to verify that files they fetch (for example, from a CDN) "
                    + "are delivered without unexpected manipulation. It works by allowing"
                    + "you to provide a cryptographic hash that a fetched file must match.";
        }

        @Override
        public String getRemediationBackground() {
            return "This is an <b>informational</b> finding only.";
        }

        @Override
        public String getIssueDetail() {
            return "Burp Scanner has identified Subresource Integrity (SRI) in the following page: <b>"
                    + reqres.getUrl().toString() + "</b><br><br>";
        }

        @Override
        public String getRemediationDetail() {
            return null;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return null;
        }

        @Override
        public IHttpService getHttpService() {
            return reqres.getHttpService();
        }
    }
}