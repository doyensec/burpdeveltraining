/*
 * Bradamsa - Burp Intruder payloads generator (simplified code - does not work!) 
 *
 * Copyright (c) 2017 Doyensec LLC. Made with love by Luca Carettoni.
 */
package com.doyensec;

import burp.BurpExtender.OS;
import burp.IBurpExtenderCallbacks;
import burp.ITab;
import java.awt.Component;

public class BradamsaTab implements ITab {

    private final BradamsaPanel bPanel;

    public BradamsaTab(final IBurpExtenderCallbacks callbacks, OS os) {

        bPanel = new BradamsaPanel(callbacks, os);
        callbacks.customizeUiComponent(bPanel);
        callbacks.addSuiteTab(BradamsaTab.this);
    }

    @Override
    public String getTabCaption() {

        return "Bradamsa";
    }

    @Override
    public Component getUiComponent() {

        return bPanel;
    }
}
