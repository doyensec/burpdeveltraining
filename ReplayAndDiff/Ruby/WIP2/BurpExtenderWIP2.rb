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
    args = callbacks.getCommandLineArguments()
    for arg in args
      if (arg.include?('-h=') || arg.include?('--host='))
        mongo_host = arg[(arg.index('=') + 1),arg.length]
      elsif (arg.include?('-p=') || arg.include?('--port='))
        mongo_port = arg[(arg.index('=') + 1),arg.length].to_i
      elsif (arg.include?('-o=') || arg.include?('--ouput='))
        output_dir = arg[(arg.index('=') + 1),arg.length]
      elsif (arg.include?('-r=') || arg.include?('--report='))
        report_name = arg[(arg.index('=') + 1),arg.length]
      elsif (arg.include?('-t=') || arg.include?('--timeout='))
        timeout = arg[(arg.index('=') + 1),arg.length].to_i
      end
    end
    System.out.println('[*] Configuration {mongo_host=' + mongo_host + ',mongo_port=' + mongo_port.to_s + ',output_dir=' + output_dir + ',report_name=' + report_name + ',timeout=' + timeout.to_s + '}')

    # 2 - Connect to MongoDB
    mongo = nil
    begin
      mongo = MongoClient.new(mongo_host, mongo_port)
    rescue UnknownHostException => ex
      System.err.println('[!] MongoDB Connection Error: ' + ex.toString())
    end

    # 3 - Retrieve login requests from the 'login' collection in db 'sitelogger'
    db = mongo.getDB('sitelogger')
    table = db.getCollection('login')
    cursor = table.find()

    host = nil
    while (cursor.hasNext())
      # 4 - For each entry, issue a new HTTP request (using Burp's makeHttpRequest) and collect the cookies (using Burp's analyzeResponse)

      # 5 - If there are cookies, update Burp's Cookies jar (using Burp's updateCookieJar)

      # TODO
    end

    # 6 - Retrieve from the database all previously saved HTTP requests
    if (host != nil)
      table = db.getCollection(host.gsub(".", '_') + '_site')
    else
      raise java.lang.NullPointerException.new()
    end

    cursor = table.find()
    website = nil
    while (cursor.hasNext())
      # 7 - Trigger a new active scan on the same URL (using Burp's doActiveScan)

      # 8 - Reissue a new HTTP request and trigger a new passive scan on the same URL (using Burp's doPassiveScan)

      # TODO
    end

    # 9 - Wait until all scans are completed
    begin
      System.out.println('[*] Pausing extension...')
      # HOMEWORK - Build a queuing system to check scans status and confirm once all scans are done
      sleep 1 * timeout
      System.out.println('[*] Resuming extension...')
    rescue InterruptedException => ex
      System.err.println('[!] InterruptedException: ' + ex.toString())
    end

    table = db.getCollection(host.gsub('.', '_') + '_vuln')
    searchQuery = nil
    allVulns = nil
    newFinding = false

    # 10 - Obtain the list of new findings (using Burp's getScanIssues)
    if (website != nil)
      allVulns = callbacks.getScanIssues(website.toString())

      for allVuln in allVulns
        # 11 - Diff old and new findings
        # For now, let's use a simple heuristic: if there's at least a new finding (not previously reported), success!
        searchQuery = BasicDBObject.new()
        searchQuery.put('type', allVuln.getIssueType())
        searchQuery.put('name', allVuln.getIssueName())
        searchQuery.put('URL', allVuln.getUrl().toString())
        System.out.println('[*] Looking for: ' + searchQuery.toString())
        cursor = table.find(searchQuery)
        if (cursor.size() == 0)
          #There's at least one new finding
          System.out.println('[*] Got a new finding!')
          newFinding = true
        end
      end

      # 12 - In case of new findings, generate the report (using Burp's generateScanReport)
      if (newFinding)

    else
      raise java.lang.NullPointerException.new()
    end
    System.out.println('[*] Ready to shutdown...Bye!')
    callbacks.exitSuite(false)
  end
end
