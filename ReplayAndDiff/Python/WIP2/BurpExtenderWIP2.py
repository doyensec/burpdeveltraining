#
# ReplayAndDiff - Replay a scan with a fresh session and diff the results
#
# Copyright (c) 2017 Doyensec LLC. Made with love by Andrea Brancaleoni.
#

from com.mongodb import BasicDBObject, DB, DBCollection, DBCursor, MongoClient
from java.io import File
from java.net import MalformedURLException, URL, UnknownHostException
from java.util import Iterator
from java.lang import System, NullPointerException, InterruptedException
from burp import IBurpExtender
from org.python.core.util import StringUtil

import time

#
# This extension can be executed in headless mode. Start burp using -Djava.awt.headless=true
#
class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):

        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        callbacks.setExtensionName('ReplayAndDiff')
        System.out.println('\n\n:: ReplayAndDiff Headless Extension ::\n\n')

        #Default configuration
        mongo_host = '127.0.0.1'
        mongo_port = 27017
        output_dir = '/tmp/'
        report_name = 'burpreport_' + str(System.currentTimeMillis()) + '.html'
        timeout = 10 #seconds

        # 1 - Parse command line arguments and store values in local variables
        # -h|--host=<IP>, -p|--port=<port>, -o|--ouput=<dir>, -r|--report=<filename>, -t|--timeout=<seconds>
        args = callbacks.getCommandLineArguments()
        for arg in args:
            if ('-h=' in arg or '--host=' in arg):
                mongo_host = arg[(arg.index('=') + 1):]
            elif ('-p=' in arg or '--port=' in arg):
                mongo_port = int(arg[(arg.index('=') + 1):])
            elif ('-o=' in arg or '--output=' in arg):
                output_dir = arg[(arg.index('=') + 1):]
            elif ('-r=' in arg or '--report=' in arg):
                report_name = arg[(arg.index('=') + 1):]
            elif ('-t=' in arg or '--timeout=' in arg):
                timeout = int(arg[(arg.index('=') + 1):])


        System.out.println('[*] Configuration {mongo_host=' + mongo_host + ',mongo_port=' + str(mongo_port) + ',output_dir=' + output_dir + ',report_name=' + report_name + ',timeout=' + str(timeout) + '}')

        # 2 - Connect to MongoDB
        mongo = None
        try:
            mongo = MongoClient(mongo_host, mongo_port)
        except UnknownHostException as ex:
            System.err.println('[!] MongoDB Connection Error: ' + ex.toString())

        # 3 - Retrieve login requests from the 'login' collection in db 'sitelogger'
        db = mongo.getDB('sitelogger')
        table = db.getCollection('login')
        cursor = table.find()

        host = None
        while (cursor.hasNext()):
            # 4 - For each entry, issue a new HTTP request (using Burp's makeHttpRequest) and collect the cookies (using Burp's analyzeResponse)

            # 5 - If there are cookies, update Burp's Cookies jar (using Burp's updateCookieJar)

            # TODO


        # 6 - Retrieve from the database all previously saved HTTP requests
        if (host != None):
            table = db.getCollection(host.replace(".", '_') + '_site')
        else:
            raise NullPointerException()

        cursor = table.find()
        website = None
        while (cursor.hasNext()):
            # 7 - Trigger a new active scan on the same URL (using Burp's doActiveScan)

            # 8 - Reissue a new HTTP request and trigger a new passive scan on the same URL (using Burp's doPassiveScan)

            # TODO

        # 9 - Wait until all scans are completed
        try:
            System.out.println('[*] Pausing extension...')
            # HOMEWORK - Build a queuing system to check scans status and confirm once all scans are done
            time.sleep(1 * timeout)
            System.out.println('[*] Resuming extension...')
        except InterruptedException as ex:
            System.err.println('[!] InterruptedException: ' + ex.toString())


        table = db.getCollection(host.replace('.', '_') + '_vuln')
        searchQuery = None
        allVulns = None
        newFinding = False

        # 10 - Obtain the list of new findings (using Burp's getScanIssues)
        if (website != None):
            allVulns = callbacks.getScanIssues(website.toString())

            for allVuln in allVulns:
                # 11 - Diff old and new findings
                # For now, let's use a simple heuristic: if there's at least a new finding (not previously reported), success!
                searchQuery = BasicDBObject()
                searchQuery.put('type', allVuln.getIssueType())
                searchQuery.put('name', allVuln.getIssueName())
                searchQuery.put('URL', allVuln.getUrl().toString())
                System.out.println('[*] Looking for: ' + searchQuery.toString())
                cursor = table.find(searchQuery)
                if (cursor.size() == 0):
                    #There's at least one new finding
                    System.out.println('[*] Got a new finding!')
                    newFinding = True


            # 12 - In case of new findings, generate the report (using Burp's generateScanReport)
            if (newFinding):
                # TODO
                pass

        else:
            raise NullPointerException()

        System.out.println('[*] Ready to shutdown...Bye!')
        callbacks.exitSuite(False)
