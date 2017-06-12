/*
 * SiteLogger - Log sitemap and findings to database
 *
 * Copyright (c) 2017 Doyensec LLC. Made with love by Luca Carettoni.
 */
package com.doyensec.sitelogger;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;
import java.awt.Component;
import javax.swing.JPanel;

public class SiteLoggerTab implements ITab {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    public SiteLoggerTab(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    @Override
    public String getTabCaption() {
        return "SiteLogger";
    }

    @Override
    public Component getUiComponent() {
        JPanel panel = new SiteLoggerPanel(callbacks, helpers);
        callbacks.customizeUiComponent(panel);
        return panel;
    }
}
