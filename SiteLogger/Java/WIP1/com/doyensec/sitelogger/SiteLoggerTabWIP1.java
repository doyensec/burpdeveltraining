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

    // 2 - Simply implement all ITab's methods (getTabCaption and getUiComponent)

    // 3 - In getUiComponent, instantiate a new Jpanel created using standard Java AWT/Swing GUI Editors
}
