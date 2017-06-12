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

        // 1 - Parse command line arguments and store values in local variables
        // -h|--host=<IP>, -p|--port=<port>, -o|--ouput=<dir>, -r|--report=<filename>, -t|--timeout=<seconds>
        
        // 2 - Connect to MongoDB

        // 3 - Retrieve login requests from the 'login' collection in db 'sitelogger'
        
        // 4 - For each entry, issue a new HTTP request (using Burp's makeHttpRequest) and collect the cookies (using Burp's analyzeResponse)
            
        // 5 - If there are cookies, update Burp's Cookies jar (using Burp's updateCookieJar)

        // 6 - Retrieve from the database all previously saved HTTP requests
        
        // 7 - Trigger a new active scan on the same URL (using Burp's doActiveScan)

        // 8 - Reissue a new HTTP request and trigger a new passive scan on the same URL (using Burp's doPassiveScan)

        // 9 - Wait until all scans are completed
        // For now, let's simply use our TIMEOUT argument to pause the execution for n seconds

        // 10 - Obtain the list of new findings (using Burp's getScanIssues)
        
        // 11 - Diff old and new findings
        // For now, let's use a simple heuristic: if there's at least a new finding (not previously reported), success!
        
        // 12 - In case of new findings, generate the report (using Burp's generateScanReport)
    }
}
