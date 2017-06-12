/*
 * ReplayAndDiff - Replay a scan with a fresh session and diff the results
 *
 * Copyright (c) 2017 Doyensec LLC. Made with love by Luca Carettoni.
 */
package burp;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.MongoClient;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Iterator;

/*
 * This extension can be executed in headless mode. Start burp using -Djava.awt.headless=true
 */
public class BurpExtender implements IBurpExtender {

    //Default configuration
    static String MONGO_HOST = "127.0.0.1";
    static int MONGO_PORT = 27017;
    static String OUTPUT_DIR = "/tmp/";
    static String REPORT_NAME = "burpreport_" + System.currentTimeMillis() + ".html";
    static int TIMEOUT = 10; //seconds

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        callbacks.setExtensionName("ReplayAndDiff");
        System.out.println("\n\n:: ReplayAndDiff Headless Extension ::\n\n");

        // 1 - Parse command line arguments and store values in local variables
        // -h|--host=<IP>, -p|--port=<port>, -o|--ouput=<dir>, -r|--report=<filename>, -t|--timeout=<seconds>
        String[] args = callbacks.getCommandLineArguments();
        for (String arg : args) {
            if (arg.contains("-h=") || arg.contains("--host=")) {
                MONGO_HOST = arg.substring(arg.indexOf('=') + 1);
            } else if (arg.contains("-p=") || arg.contains("--port=")) {
                MONGO_PORT = Integer.valueOf(arg.substring(arg.indexOf('=') + 1));
            } else if (arg.contains("-o=") || arg.contains("--output=")) {
                OUTPUT_DIR = arg.substring(arg.indexOf('=') + 1);
            } else if (arg.contains("-r=") || arg.contains("--report=")) {
                REPORT_NAME = arg.substring(arg.indexOf('=') + 1);
            } else if (arg.contains("-t=") || arg.contains("--timeout=")) {
                TIMEOUT = Integer.valueOf(arg.substring(arg.indexOf('=') + 1));
            }
        }
        System.out.println("[*] Configuration {MONGO_HOST=" + MONGO_HOST + ",MONGO_PORT=" + MONGO_PORT + ",OUTPUT_DIR=" + OUTPUT_DIR + ",REPORT_NAME=" + REPORT_NAME + ",TIMEOUT=" + TIMEOUT + "}");

        // 2 - Connect to MongoDB
        MongoClient mongo = null;
        try {
            mongo = new MongoClient(MONGO_HOST, MONGO_PORT);
        } catch (UnknownHostException ex) {
            System.err.println("[!] MongoDB Connection Error: " + ex.toString());
        }

        // 3 - Retrieve login requests from the 'login' collection in db 'sitelogger'
        DB db = mongo.getDB("sitelogger");
        DBCollection table = db.getCollection("login");
        DBCursor cursor = table.find();


        String host = null;
        while (cursor.hasNext()) {

            // 4 - For each entry, issue a new HTTP request (using Burp's makeHttpRequest) and collect the cookies (using Burp's analyzeResponse)
            
            // 5 - If there are cookies, update Burp's Cookies jar (using Burp's updateCookieJar)
            
            // TODO
        }

        // 6 - Retrieve from the database all previously saved HTTP requests
        if (host != null) {
            table = db.getCollection(host.replaceAll("\\.", "_") + "_site");
        } else {
            throw new NullPointerException();
        }
        cursor = table.find();
        URL website = null;
        while (cursor.hasNext()) {

            // 7 - Trigger a new active scan on the same URL (using Burp's doActiveScan)

            // 8 - Reissue a new HTTP request and trigger a new passive scan on the same URL (using Burp's doPassiveScan)

            // TODO
        }

        // 9 - Wait until all scans are completed
        try {
            System.out.println("[*] Pausing extension...");
            // HOMEWORK - Build a queuing system to check scans status and confirm once all scans are done
            Thread.sleep(1000 * TIMEOUT);
            System.out.println("[*] Resuming extension...");
        } catch (InterruptedException ex) {
            System.err.println("[!] InterruptedException: " + ex.toString());
        }

        table = db.getCollection(host.replaceAll("\\.", "_") + "_vuln");
        BasicDBObject searchQuery = null;
        IScanIssue[] allVulns = null;
        boolean newFinding = false;

        // 10 - Obtain the list of new findings (using Burp's getScanIssues)
        if (website != null) {
            allVulns = callbacks.getScanIssues(website.toString());

            for (IScanIssue allVuln : allVulns) {
                // 11 - Diff old and new findings
                // For now, let's use a simple heuristic: if there's at least a new finding (not previously reported), success!
                searchQuery = new BasicDBObject();
                searchQuery.put("type", allVuln.getIssueType());
                searchQuery.put("name", allVuln.getIssueName());
                searchQuery.put("URL", allVuln.getUrl().toString());
                System.out.println("[*] Looking for: " + searchQuery.toString());
                cursor = table.find(searchQuery);
                if (cursor.size() == 0) {
                    //There's at least one new finding
                    System.out.println("[*] Got a new finding!");
                    newFinding = true;
                }
            }

            // 12 - In case of new findings, generate the report (using Burp's generateScanReport)
            if (newFinding) {
                // TODO
            } 

        } else {
            throw new NullPointerException();
        }
        System.out.println("[*] Ready to shutdown...Bye!");
        callbacks.exitSuite(false);
    }
}
