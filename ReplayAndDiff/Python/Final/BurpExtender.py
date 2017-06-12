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

        #Parse command line arguments and store values in local variables
        #-h|--host=<IP>, -p|--port=<port>, -o|--ouput=<dir>, -r|--report=<filename>, -t|--timeout=<seconds>
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

        #Retrieve site info and login request from MongoDB
        mongo = None
        try:
            mongo = MongoClient(mongo_host, mongo_port)
        except UnknownHostException as ex:
            System.err.println('[!] MongoDB Connection Error: ' + ex.toString())


        db = mongo.getDB('sitelogger')
        table = db.getCollection('login')
        cursor = table.find()

        host = None
        while (cursor.hasNext()):
            entry = cursor.next()
            #Replay the HTTP request and save the fresh cookie in Burp's Cookies JAR
            host = entry.get('host')
            System.out.println('[*] Retrieving record for: ' + host)
            response = callbacks.makeHttpRequest(host, int(entry.get('port')), 'https' == entry.get('protocol'), self.b64d(entry.get('request')))
            cookies = self.helpers.analyzeResponse(response).getCookies().iterator()
            while (cookies.hasNext()):
                try:
                    cookie = cookies.next()
                    System.out.println('[*] Obtained cookie: ' + cookie.getName() + ':' + cookie.getValue())
                    callbacks.updateCookieJar(cookie)
                except NullPointerException as npe:
                    System.out.println('[!] Missing cookie attributes - e.g. domain not set')




        #Replay a scan on all URLs previously saved for the same site
        if (host != None):
            table = db.getCollection(host.replace(".", '_') + '_site')
        else:
            raise NullPointerException()

        cursor = table.find()
        website = None
        while (cursor.hasNext()):
            entry = cursor.next()
            #Add host in scope. This is meant to prevent popup since the extension is running headless
            try:
                website = URL((entry.get('protocol')) + '://' + (entry.get('host')))
                callbacks.includeInScope(website)

                #Execute passive and active scans
                item = callbacks.doActiveScan(entry.get('host'), entry.get('port'), 'https' == entry.get('protocol'), self.b64d(entry.get('request')))
                #Make a new HTTP request and pass request/response to Burp's passive scanner
                response = callbacks.makeHttpRequest(entry.get('host'), int(entry.get('port')), 'https' == entry.get('protocol'), self.b64d(entry.get('request')))
                callbacks.doPassiveScan(entry.get('host'), entry.get('port'), 'https' == entry.get('protocol'), self.b64d(entry.get('request')), response)

            except MalformedURLException as ex:
                System.err.println('[!] Malformed website URL: ' + ex.toString())
            except NullPointerException as ex:
                System.err.println('[!] Missing request or response: ' + ex.toString())



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

        #Obtain the new scan findings
        if (website != None):
            allVulns = callbacks.getScanIssues(website.toString())

            for allVuln in allVulns:
                #Diff new and old scan results.
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



            if (newFinding):
                System.out.println('[*] New findings! Generating report...')
                callbacks.generateScanReport('HTML', allVulns, File(output_dir + report_name))
            else:
                System.out.println('[*] Scan and diff completed. No new results.')


        else:
            raise NullPointerException()

        System.out.println('[*] Ready to shutdown...Bye!')
        callbacks.exitSuite(False)

    # Utility method to Base64 decode
    def b64d(self, input):
        if (input != None):
            return self.helpers.base64Decode(input)
        return StringUtil.toBytes('')
