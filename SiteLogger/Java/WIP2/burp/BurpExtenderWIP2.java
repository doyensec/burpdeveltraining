/*
 * SiteLogger - Log sitemap and findings to database
 *
 * Copyright (c) 2017 Doyensec LLC. Made with love by Luca Carettoni.
 */
package burp;

import com.doyensec.sitelogger.SiteLoggerTab;

public class BurpExtender implements IBurpExtender {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("SiteLogger");

        // 1 - Add a custom tab to Burp (using addSuiteTab)
        // Please use a separate file named 'SiteLoggerTab' within the package 'com.doyensec.sitelogger'
        callbacks.addSuiteTab(new SiteLoggerTab(callbacks, helpers));
    }
}
