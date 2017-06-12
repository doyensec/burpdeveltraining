#
# ReplayAndDiff - Replay a scan with a fresh session and diff the results
#
# Copyright (c) 2017 Doyensec LLC. Made with love by Andrea Brancaleoni.
#
require 'java'

java_import 'com.mongodb.BasicDBObject'
java_import 'com.mongodb.DB'
java_import 'com.mongodb.DBCollection'
java_import 'com.mongodb.DBCursor'
java_import 'com.mongodb.DBObject'
java_import 'com.mongodb.MongoClient'
java_import 'java.io.File'
java_import 'java.net.MalformedURLException'
java_import 'java.net.URL'
java_import 'java.net.UnknownHostException'
java_import 'java.util.Iterator'
java_import 'burp.IBurpExtender'
java_import 'java.lang.System'
java_import 'java.lang.InterruptedException'

#
# This extension can be executed in headless mode. Start burp using -Djava.awt.headless=true
#
class BurpExtender
  include IBurpExtender
  attr_accessor :helpers

  def registerExtenderCallbacks(callbacks)

    @callbacks = callbacks
    @helpers = callbacks.getHelpers()

    callbacks.setExtensionName('ReplayAndDiff')
    System.out.println("\n\n:: ReplayAndDiff Headless Extension ::\n\n")

    #Default configuration
    mongo_host = '127.0.0.1'
    mongo_port = 27017
    output_dir = '/tmp/'
    report_name = 'burpreport_' + System.currentTimeMillis().to_s + '.html'
    timeout = 10 #seconds


    # 1 - Parse command line arguments and store values in local variables
    # -h|--host=<IP>, -p|--port=<port>, -o|--ouput=<dir>, -r|--report=<filename>, -t|--timeout=<seconds>

    # 2 - Connect to MongoDB

    # 3 - Retrieve login requests from the 'login' collection in db 'sitelogger'

    # 4 - For each entry, issue a new HTTP request (using Burp's makeHttpRequest) and collect the cookies (using Burp's analyzeResponse)

    # 5 - If there are cookies, update Burp's Cookies jar (using Burp's updateCookieJar)

    # 6 - Retrieve from the database all previously saved HTTP requests

    # 7 - Trigger a new active scan on the same URL (using Burp's doActiveScan)

    # 8 - Reissue a new HTTP request and trigger a new passive scan on the same URL (using Burp's doPassiveScan)

    # 9 - Wait until all scans are completed
    # For now, let's simply use our TIMEOUT argument to pause the execution for n seconds

    # 10 - Obtain the list of new findings (using Burp's getScanIssues)

    # 11 - Diff old and new findings
    # For now, let's use a simple heuristic: if there's at least a new finding (not previously reported), success!

    # 12 - In case of new findings, generate the report (using Burp's generateScanReport)
  end
end
