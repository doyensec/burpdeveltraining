/*
 * SiteLogger - Log sitemap and findings to database
 *
 * Copyright (c) 2017 Doyensec LLC. Made with love by Luca Carettoni.
 */
package com.doyensec.sitelogger;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.MongoClient;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

public class SiteLoggerPanel extends javax.swing.JPanel {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    public SiteLoggerPanel(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        initComponents();
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    private void initComponents() {

        // 4 - Define here the AWT/Swing UI which should contain three text fields (mongohost, mongoport, website) and save button

        // TODO

        // *** Highly recommended to use a WYSIWYG editor ***
    }

    // Button Event Click - Our code goes here!
    private void logButtonActionPerformed(java.awt.event.ActionEvent evt) {

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);

        try {
            // 5 - Connect to the database and create two new collections for storing sitemap and vulns
            MongoClient mongo = new MongoClient(mongohost.getText(), Integer.parseInt(mongoport.getText()));
            DB db = mongo.getDB("sitelogger");
            URL siteUrl = new URL(website.getText());
            DBCollection tableSite = db.getCollection(siteUrl.getHost().replaceAll("\\.", "_") + "_site");
            DBCollection tableVuln = db.getCollection(siteUrl.getHost().replaceAll("\\.", "_") + "_vuln");

            // 6 - Retrieve the SiteMap content (using Burp's getSiteMap)
            IHttpRequestResponse[] allReqRes = callbacks.getSiteMap(website.getText());
            for (int rc = 0; rc < allReqRes.length; rc++) {
                // 7 - Save each HTTP request/response to the database
                BasicDBObject document = new BasicDBObject();
                document.put("host", allReqRes[rc].getHost());
                document.put("port", allReqRes[rc].getPort());
                document.put("protocol", allReqRes[rc].getProtocol());
                document.put("URL", allReqRes[rc].getUrl().toString());
                document.put("status_code", allReqRes[rc].getStatusCode());
                if (allReqRes[rc].getRequest() != null) {
                    document.put("request", helpers.base64Encode(allReqRes[rc].getRequest()));
                }
                if (allReqRes[rc].getResponse() != null) {
                    document.put("response", helpers.base64Encode(allReqRes[rc].getResponse()));
                }
                tableSite.insert(document);
            }

            // 8 - Retrieve all scanner findings (using Burp's getScanIssues)
            IScanIssue[] allVulns = callbacks.getScanIssues(website.getText());
            for (int vc = 0; vc < allVulns.length; vc++) {
                // 9 - Save each vulnerability report to the database, including HTTP request/response
                BasicDBObject document = new BasicDBObject();
                document.put("type", allVulns[vc].getIssueType());
                document.put("name", allVulns[vc].getIssueName());
                document.put("detail", allVulns[vc].getIssueDetail());
                document.put("severity", allVulns[vc].getSeverity());
                document.put("confidence", allVulns[vc].getConfidence());
                document.put("host", allVulns[vc].getHost());
                document.put("port", allVulns[vc].getPort());
                document.put("protocol", allVulns[vc].getProtocol());
                document.put("URL", allVulns[vc].getUrl().toString());
                if (allVulns[vc].getHttpMessages().length > 1) {
                    if (allVulns[vc].getHttpMessages()[0].getRequest() != null) {
                        document.put("request", helpers.base64Encode(allVulns[vc].getHttpMessages()[0].getRequest()));
                    }
                    if (allVulns[vc].getHttpMessages()[0].getResponse() != null) {
                        document.put("response", helpers.base64Encode(allVulns[vc].getHttpMessages()[0].getResponse()));
                    }
                }
                tableVuln.insert(document);
            }

            callbacks.issueAlert("Data Saved!");

        } catch (UnknownHostException ex) {
            
            stderr.println("Mongo DB Connection Error:" + ex.toString());
            
        } catch (MalformedURLException ex) {
            
            stderr.println("Malformed URL:" + ex.toString());
            
        }
    }
}
