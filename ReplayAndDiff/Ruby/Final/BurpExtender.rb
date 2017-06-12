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

    #Parse command line arguments and store values in local variables
    #-h|--host=<IP>, -p|--port=<port>, -o|--ouput=<dir>, -r|--report=<filename>, -t|--timeout=<seconds>
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

    #Retrieve site info and login request from MongoDB
    mongo = nil
    begin
      mongo = MongoClient.new(mongo_host, mongo_port)
    rescue UnknownHostException => ex
      System.err.println('[!] MongoDB Connection Error: ' + ex.toString())
    end

    db = mongo.getDB('sitelogger')
    table = db.getCollection('login')
    cursor = table.find()

    host = nil
    while (cursor.hasNext())
      entry = cursor.next()
      #Replay the HTTP request and save the fresh cookie in Burp's Cookies JAR
      host = entry.get('host')
      System.out.println('[*] Retrieving record for: ' + host)
      response = callbacks.makeHttpRequest(host, entry.get('port').to_i, 'https' == entry.get('protocol'), b64d(entry.get('request')))
      cookies = helpers.analyzeResponse(response).getCookies().iterator()
      while (cookies.hasNext())
        begin
          cookie = cookies.next()
          System.out.println('[*] Obtained cookie: ' + cookie.getName() + ':' + cookie.getValue())
          callbacks.updateCookieJar(cookie)
        rescue java.lang.NullPointerException => npe
          System.out.println('[!] Missing cookie attributes - e.g. domain not set')
        end
      end
    end

    #Replay a scan on all URLs previously saved for the same site
    if (host != nil)
      table = db.getCollection(host.gsub(".", '_') + '_site')
    else
      raise java.lang.NullPointerException.new()
    end
    cursor = table.find()
    website = nil
    while (cursor.hasNext())
      entry = cursor.next()
      #Add host in scope. This is meant to prevent popup since the extension is running headless
      begin
        website = URL.new((entry.get('protocol')) + '://' + (entry.get('host')))
        callbacks.includeInScope(website)

        #Execute passive and active scans
        item = callbacks.doActiveScan(entry.get('host'), entry.get('port'), 'https' == entry.get('protocol'), b64d(entry.get('request')))

        #Make a new HTTP request and pass request/response to Burp's passive scanner
        response = callbacks.makeHttpRequest(entry.get('host'), entry.get('port').to_i, 'https' == entry.get('protocol'), b64d(entry.get('request')))
        callbacks.doPassiveScan(entry.get('host'), entry.get('port'), 'https' == entry.get('protocol'), b64d(entry.get('request')), response)

      rescue MalformedURLException => ex
        System.err.println('[!] Malformed website URL: ' + ex.toString())
      rescue java.lang.NullPointerException => ex
        System.err.println('[!] Missing request or response: ' + ex.toString())
      end
    end

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

    #Obtain the new scan findings
    if (website != nil)
      allVulns = callbacks.getScanIssues(website.toString())

      for allVuln in allVulns
        #Diff new and old scan results.
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

      if (newFinding)
        System.out.println('[*] New findings! Generating report...')
        callbacks.generateScanReport('HTML', allVulns, File.new(output_dir + report_name))
      else
        System.out.println('[*] Scan and diff completed. No new results.')
      end

    else
      raise java.lang.NullPointerException.new()
    end
    System.out.println('[*] Ready to shutdown...Bye!')
    callbacks.exitSuite(false)
  end

  # Utility method to Base64 decode
  def b64d(input)
    if input
      return helpers.base64Decode(input)
    end
    return "".to_java_bytes
  end
end
