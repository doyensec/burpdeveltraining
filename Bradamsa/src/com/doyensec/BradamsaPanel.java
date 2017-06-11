/*
 * Bradamsa - Burp Intruder payloads generator (simplified code - does not work!) 
 *
 * Copyright (c) 2017 Luca Carettoni - Doyensec LLC.
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

    // Java Swing UI code here

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
        //Output directory - mandatory
        if (validateOutput()) {
            output.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
            cmdline.setForeground(new java.awt.Color(0, 153, 102));
            cmdSB.append(" -o ");
            cmdSB.append(output.getText().toLowerCase().trim());
        } else {
            output.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Missing output directory or incorrect permissions");
            return "";
        }
        //Seed - optional
        if (validateSeed()) {
            if (!seed.getText().toLowerCase().trim().isEmpty()) {
                seed.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
                cmdline.setForeground(new java.awt.Color(0, 153, 102));
                cmdSB.append(" -s ");
                cmdSB.append(seed.getText().toLowerCase().trim());
            } else {
                seed.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153), 2));
            }
        } else {
            seed.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Seed is not 'number'");
            return "";
        }
        //Mutations - optional
        if (validateMutations()) {
            if (!mutations.getText().toLowerCase().trim().isEmpty()) {
                mutations.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
                cmdline.setForeground(new java.awt.Color(0, 153, 102));
                cmdSB.append(" -m ");
                cmdSB.append(mutations.getText().toLowerCase().trim());
            } else {
                mutations.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153), 2));
            }
        } else {
            mutations.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Invalid mutations [ft=2,fo=2,fn,num=3,td,tr2,ts1,tr,ts2,ld,lr2,li,ls,lp,lr,sr,bd,bf,bi,br,bp,bei,bed,ber,uw,ui]");
            return "";
        }
        //Patterns - optional
        if (validatePatterns()) {
            if (!patterns.getText().toLowerCase().trim().isEmpty()) {
                patterns.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
                cmdline.setForeground(new java.awt.Color(0, 153, 102));
                cmdSB.append(" -p ");
                cmdSB.append(patterns.getText().toLowerCase().trim());
            } else {
                patterns.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153), 2));
            }
        } else {
            patterns.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Invalid mutations pattern [od,nd,bu]");
            return "";
        }
        //Meta - optional
        if (validateMeta()) {
            if (!meta.getText().toLowerCase().trim().isEmpty()) {
                meta.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
                cmdline.setForeground(new java.awt.Color(0, 153, 102));
                cmdSB.append(" -M ");
                cmdSB.append(meta.getText().toLowerCase().trim());
            } else {
                meta.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153), 2));
            }
        } else {
            meta.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Missing metadata directory or incorrect permissions");
            return "";
        }

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

    protected boolean validateOutput() {

        String outputStr = output.getText().toLowerCase().trim();
        if (outputStr.isEmpty()) {
            return false;
        }

        File f = new File(outputStr.substring(0, outputStr.lastIndexOf(File.separatorChar)));
        return f.exists() && f.isDirectory();
    }

    protected boolean validateSeed() {

        if (seed.getText().toLowerCase().trim().isEmpty()) {
            return true;
        }

        try {
            Long.valueOf(seed.getText().toLowerCase().trim());
        } catch (NumberFormatException numExc) {
            return false;
        }

        return true;
    }

    protected boolean validateMutations() {

        if (mutations.getText().toLowerCase().trim().isEmpty()) {
            return true;
        }

        return Pattern.matches("(\\p{Alnum}+)(=\\p{Digit}+)?(,(\\p{Alnum}+)(=\\p{Digit}+)?)*", mutations.getText().toLowerCase().trim());
    }

    protected boolean validatePatterns() {

        if (patterns.getText().toLowerCase().trim().isEmpty()) {
            return true;
        }

        return Pattern.matches("(od|nd|bu)+(,(od|nd|bu))*", patterns.getText().toLowerCase().trim());
    }

    protected boolean validateMeta() {

        String metaStr = meta.getText().toLowerCase().trim();
        if (metaStr.isEmpty()) {
            return true;
        }

        if (!metaStr.contains(String.valueOf(File.separatorChar))) {
            return false;
        }
        
        if (metaStr.charAt(metaStr.length()-1) == File.separatorChar) {
            return false;
        }

        File f = new File(metaStr.substring(0, metaStr.lastIndexOf(File.separatorChar)));
        return f.exists() && f.isDirectory();
    }

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
