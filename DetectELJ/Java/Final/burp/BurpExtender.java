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

        byte[] withPayload = isip.buildRequest("${1336+1}".getBytes());
        IHttpRequestResponse newReqRes = callbacks.makeHttpRequest(ihrr.getHttpService(), withPayload);

        IResponseVariations variation = helpers.analyzeResponseVariations(ihrr.getResponse(), newReqRes.getResponse());
        List<String> pageChanges = variation.getVariantAttributes();

        boolean length = false;
        boolean bodyContent = false;
        boolean match = false;

        for (String change : pageChanges) {
            if (change.equals("content_length")) length = true;
            if (change.equals("whole_body_content")) bodyContent = true;
        }

        if (helpers.bytesToString(newReqRes.getResponse()).contains("1337")) match = true;

        if (length && bodyContent && match) {
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new ELJ(newReqRes));
            return issues;
        } else {
            return null;
        }
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue isb, IScanIssue isa) {
        if (Arrays.equals(isb.getHttpMessages()[0].getResponse(), isa.getHttpMessages()[0].getResponse())) {
            return -1;
        } else {
            return 0;
        }
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
            String strRes = helpers.bytesToString(reqres.getResponse());
            int[] marks = new int[2];
            marks[0] = strRes.indexOf("1337");
            marks[1] = marks[0] + 4;
            List<int[]> marksList = new ArrayList<>(1);
            marksList.add(marks);
            IHttpRequestResponseWithMarkers reqresMark = callbacks.applyMarkers(reqres, null, marksList);
            IHttpRequestResponse[] rra = { reqresMark };
            return rra;
        }

        @Override
        public IHttpService getHttpService() {
            return reqres.getHttpService();
        }
    }
}
