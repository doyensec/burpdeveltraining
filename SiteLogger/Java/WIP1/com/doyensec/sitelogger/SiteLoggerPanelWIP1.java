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

        // *** Highly recommended to use a WYSIWYG editor ***
    }

    // Button Event Click - Our code goes here!
    private void logButtonActionPerformed(java.awt.event.ActionEvent evt) {

        // 5 - Connect to the database and create two new collections for storing sitemap and vulns
            
        // 6 - Retrieve the SiteMap content (using Burp's getSiteMap)
            
        // 7 - Save each HTTP request/response to the database
               
        // 8 - Retrieve all scanner findings (using Burp's getScanIssues)
           
        // 9 - Save each vulnerability report to the database, including HTTP request/response 
    }
}
