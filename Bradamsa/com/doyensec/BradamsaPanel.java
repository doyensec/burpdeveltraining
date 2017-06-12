/*
 * Bradamsa - Burp Intruder payloads generator (simplified code - does not work!) 
 *
 * Copyright (c) 2017 Doyensec LLC. Made with love by Luca Carettoni.
 */
package com.doyensec;

import burp.BurpExtender;
import burp.BurpExtender.OS;
import burp.IBurpExtenderCallbacks;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;
import javax.swing.JOptionPane;

public final class BradamsaPanel extends javax.swing.JPanel {

    private final IBurpExtenderCallbacks callbacks;
    private final OS os;

    public BradamsaPanel(IBurpExtenderCallbacks callbacks, OS os) {

        initComponents();
        this.callbacks = callbacks;
        this.os = os;

        //Initialize Radamsa options
        resetSettings();
        
        JOptionPane.showMessageDialog(null, "<html><b>Bradamsa</b> allows to generate Intruder payloads using <i>Radamsa</i>. "
                + "<br>The current version supports <u>sniper</u> attack type only!</html>", ":: Welcome to Bradamsa ::", JOptionPane.INFORMATION_MESSAGE);
    }

    // Java Swing UI code HERE

    /*
     * Validate and return Radamsa command line 
     * @return the full command string or an empty string (in case of invalid input)
     */
    protected String getRadamsaCmdLine() {

        StringBuilder cmdSB = new StringBuilder();

        //Radamsa binary path - mandatory
        if (validateBinary()) {
            binary.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
            cmdline.setForeground(new java.awt.Color(0, 153, 102));
            cmdSB.append(binary.getText().toLowerCase().trim());
        } else {
            binary.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Invalid Radamsa binary path. Have you installed it? Where?");
            return "";
        }
        //Samples count - mandatory
        if (validateCount()) {
            count.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
            cmdline.setForeground(new java.awt.Color(0, 153, 102));
            cmdSB.append(" -n ");
            cmdSB.append(count.getText().toLowerCase().trim());
        } else {
            count.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Count option is not 'number'");
            return "";
        }

        //Other command line validation and display HERE

        cmdline.setText(cmdSB.toString());
        return cmdSB.toString();
    }

    protected boolean validateBinary() {

        if (binary.getText().toLowerCase().trim().isEmpty()) {
            return false;
        }
        File f = new File(binary.getText().toLowerCase().trim());
        return f.exists() && !f.isDirectory();
    }

    protected boolean validateCount() {

        try {
            Long.valueOf(count.getText().toLowerCase().trim());
        } catch (NumberFormatException numExc) {
            return false;
        }
        return true;
    }

    protected boolean validatePatterns() {

        if (patterns.getText().toLowerCase().trim().isEmpty()) {
            return true;
        }

        return Pattern.matches("(od|nd|bu)+(,(od|nd|bu))*", patterns.getText().toLowerCase().trim());
    }


    //Other validation methods HERE

    protected File getOutputDir() {

        String outputStr = output.getText().toLowerCase().trim();
        File fout = new File(outputStr.substring(0, outputStr.lastIndexOf(File.separatorChar)));

        return fout;
    }

    protected Long getCount() {

        try {
            return Long.valueOf(count.getText().toLowerCase().trim());
        } catch (NumberFormatException numExc) {
            return (long) 0;
        }
    }

    protected boolean deleteFiles() {

        return deleteAll.isSelected();
    }

    private void resetSettings() {

        //Radamsa binary path
        if (os.equals(BurpExtender.OS.LINUX)) {
            binary.setText("/usr/bin/radamsa");
        } else if (os.equals(BurpExtender.OS.MAC)) {
            binary.setText("/usr/bin/radamsa");
        } else if (os.equals(BurpExtender.OS.WIN)) {
            binary.setText("Add here radamsa-0.3.exe filepath");
        } else {
            binary.setText("Add here the Radamsa binary path");
        }

        //Samples count
        count.setText("10");

        //Output directory
        try {
            //Create default temporary directory for samples
            Path tmpDirectory = Files.createTempDirectory("radamsa");
            tmpDirectory.toFile().deleteOnExit();
            output.setText(tmpDirectory.toFile().getAbsolutePath() + File.separatorChar + "%n.out");
        } catch (IOException ex) {
            new PrintWriter(callbacks.getStdout()).println("[!] Bradamsa Exception: BradamsaPanel IOException");
        }

        seed.setText("");
        mutations.setText("");
        patterns.setText("");
        meta.setText("");
        deleteAll.setSelected(true);
        cmdline.setText(getRadamsaCmdLine());
    }
}
