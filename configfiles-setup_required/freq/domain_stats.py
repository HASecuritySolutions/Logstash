#domain_stats.py by Mark Baggett
#Twitter @MarkBaggett

from __future__ import print_function
import BaseHTTPServer
import threading
import SocketServer
import urlparse
import re
import argparse
import sys
import time
import os
import datetime

try:
    import whois
except Exception as e:
    print(str(e))
    print("You need to install the Python whois module.  Install PIP (https://bootstrap.pypa.io/get-pip.py).  Then 'pip install python-whois' ")
    sys.exit(0)

class domain_api(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        print(self.path)
        (ignore, ignore, urlpath, urlparams, ignore) = urlparse.urlsplit(self.path)
        cmdstr = tgtstr = None
        print(urlparams)
        if re.search("[\/](?:created|alexa|domain)[\/].*?", urlpath):
            cmdstr = re.search(r"[\/](created|alexa|domain)[\/].*$", urlpath)
            tgtstr = re.search(r"[\/](created|alexa|domain)[\/](.*)$", urlpath)
            if not cmdstr or not tgtstr:
                self.wfile.write('<html><body>API Documentation<br> http://%s:%s/cmd/tgt <br> cmd = domain, alexa or created <br> tgt = domain name </body></html>' % (self.server.server_address[0], self.server.server_address[1],self.server.server_address[0], self.server.server_address[1],self.server.server_address[0], self.server.server_address[1]))
                return
            params = {}
            params["cmd"] = cmdstr.group(1)
            params["tgt"] = tgtstr.group(2)
        else:
            cmdstr=re.search("cmd=(?:domain|alexa|created)",urlparams)
            tgtstr =  re.search("tgt=",urlparams)
            if not cmdstr or not tgtstr:
                self.wfile.write('<html><body>API Documentation<br> http://%s:%s/?cmd=measure&tgt=&ltstring&gt <br> http://%s:%s/?cmd=normal&tgt=&ltstring&gt <br> http://%s:%s/?cmd=normal&tgt=&ltstring&gt&weight=&ltweight&gt </body></html>' % (self.server.server_address[0], self.server.server_address[1],self.server.server_address[0], self.server.server_address[1],self.server.server_address[0], self.server.server_address[1]))
                return
            params={}
            try:
                for prm in urlparams.split("&"):
                    key,value = prm.split("=")
                    params[key]=value
            except:
                self.wfile.write('<html><body>Unable to parse the url. </body></html>')
                return
        if params["cmd"] == "alexa":
            if self.server.verbose: self.server.safe_print ("Alexa Query:", params["tgt"])
            if not self.server.alexa:
                if self.server.verbose: self.server.safe_print ("No Alexa data loaded. Restart program.")
                self.wfile.write("Alexa not loaded on server. Restart server with -a or --alexa and file path.")
            else:
                if self.server.verbose: self.server.safe_print ("Alexa queried for:%s" % (params['tgt']))              
                self.wfile.write(str(self.server.alexa.get(params["tgt"],"0")))
        elif params["cmd"] == "domain" or params["cmd"] == "created":
            if params['tgt'] in self.server.cache:
                print("Found in cache!!")
                domain_info = self.server.cache.get(params['tgt'])
            else:
                try:
                    print ("Querying the web", params['tgt'])
                    domain_info = whois.whois(params['tgt'])
                    if not domain_info.get('creation_date'):
                        self.wfile.write(str("No whois record for %s" % (params['tgt'])))
                        return
                except Exception as e:
                    if self.server.verbose: self.server.safe_print ("Error querying whois server: %s" % (str(e)))
                    
                    return
            self.server.safe_print("Caching whois record %s" % (str(domain_info)))
            domain_info["time"] = time.time()
            if self.server.alexa:
                domain_info['alexa'] = self.server.alexa.get(params["tgt"],"0")
            try:
                self.server.cache_lock.acquire()
                self.server.cache[params['tgt']] = domain_info
            finally:
                self.server.cache_lock.release()
            if params["cmd"] == "created":
                self.wfile.write(domain_info.get('creation_date','not found').__str__())
            elif params["cmd"] =="domain":
                self.wfile.write(str(domain_info))
        return

    def log_message(self, format, *args):
        return

class ThreadedDomainStats(SocketServer.ThreadingMixIn, SocketServer.TCPServer, BaseHTTPServer.HTTPServer):
    def __init__(self, *args,**kwargs):
        self.cache = {}
        self.cache_lock = threading.Lock()
        self.cache_time = 1
        self.screen_lock = threading.Lock()
        self.alexa = ""
        self.verbose = False
        self.exitthread = threading.Event()
        self.exitthread.clear()
        BaseHTTPServer.HTTPServer.__init__(self, *args, **kwargs)

    def safe_print(self,*args,**kwargs):
        try:
            self.screen_lock.acquire()
            print(*args,**kwargs)
        finally:
            self.screen_lock.release()

    def clear_old_cache(self):
        if self.verbose: self.safe_print ( "Clearing old cache")
        try:
            self.cache_lock.acquire()
            for item in self.cache:
                if (self.cache[item].get('time', time.time()) - time.time()) > self.cache_time*60*60:
                    del self.cache[item]
        finally:
            self.cache_lock.release()
        #Reschedule yourself to run again in 1 hour
        if not self.exitthread.isSet():
            self.timer = threading.Timer(60*60, self.clear_old_cache, args = ())
            self.timer.start()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('-ip','--address',required=False,help='IP Address for the server to listen on.  Default is 127.0.0.1',default='127.0.0.1')
    parser.add_argument('-c','--cache_time',type=float,required=False,help='Number of hours to hold a whois record in the cache. Default is 1 hour. Set to 0 to save forever.',default=1)
    parser.add_argument('port',type=int,help='You must provide a TCP Port to bind to')
    parser.add_argument('-v','--verbose',action='count',required=False,help='Print verbose output to the server screen.  -vv is more verbose.')
    parser.add_argument('-a','--alexa',required=False,help='Provide a local file path to an Alexa top-1m.csv')

    #args = parser.parse_args("-s 1 -vv 8081 english_lowercase.freq".split())
    args = parser.parse_args()

    #Setup the server.
    server = ThreadedDomainStats((args.address, args.port), domain_api)
    if args.alexa:
        if not os.path.exists(args.alexa):
            print("Alexa file not found %s" % (args.alexa))
        else:
            try:
                server.alexa = dict([(a,b) for b,a in re.findall(r"^(\d+),(.*)", open(args.alexa).read(), re.MULTILINE)])
            except Exception as e:
                print("Unable to parse alexa file:%s" % (str(e)))
    server.verbose = args.verbose
    server.cache_time = args.cache_time
    #Schedule the first save interval unless save_interval was set to 0.
    if args.cache_time:
        server.timer = threading.Timer(60 *args.cache_time, server.clear_old_cache, args = ())
        server.timer.start()
 
    #start the server
    print('Server is Ready. http://%s:%s/?cmd=measure&tgt=astring' % (args.address, args.port))
    print('[?] - Remember: If you are going to call the api with wget, curl or something else from the bash prompt you need to escape the & with \& \n\n')
    while True:
        try:
            server.handle_request()
        except KeyboardInterrupt:
            break

    server.timer.cancel()    
    server.safe_print("Web API Disabled...")
    server.safe_print("Control-C hit: Exiting server.  Please wait..")

if __name__=="__main__":
    main()