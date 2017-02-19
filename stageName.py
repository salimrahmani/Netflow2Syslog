from multiprocessing import Process
from ConfigParser import SafeConfigParser
import subprocess, signal
import sys, os
import syslog
import commands
import logging, logging.handlers
import argparse
import requests
import pynfdump
import pyinotify
import netsyslog

__author__= 'Salim Rahmani' 

class Util:

	# convert string from config file to facility!
	@staticmethod
	def str2facility(f):
		if(f=="LOG_AUTH"):
			return syslog.LOG_AUTH
		if(f=="LOG_AUTHPRIV"):
			return syslog.LOG_AUTHPRIV
		if(f=="LOG_CRON"):
			return syslog.LOG_CRON
		if(f=="LOG_DAEMON"):
			return syslog.LOG_DAEMON
		if(f=="LOG_FTP"):
			return syslog.LOG_FTP
		if(f=="LOG_KERN"):
			return syslog.LOG_KERN
		if(f=="LOG_LPR"):
			return syslog.LOG_LPR
		if(f=="LOG_MAIL"):
			return syslog.LOG_MAIL
		if(f=="LOG_NEWS"):
			return syslog.LOG_NEWS
		if(f=="LOG_SYSLOG"):
			return syslog.LOG_SYSLOG
		if(f=="LOG_USER"):
			return syslog.LOG_USER
		if(f=="LOG_UUCP"):
			return syslog.LOG_UUCP
		if(f=="LOG_LOCAL0"):
			return syslog.LOG_LOCAL0
		if(f=="LOG_LOCAL1"):
			return syslog.LOG_LOCAL1
		if(f=="LOG_LOCAL2"):
			return syslog.LOG_LOCAL2
		if(f=="LOG_LOCAL3"):
			return syslog.LOG_LOCAL3
		if(f=="LOG_LOCAL4"):
			return syslog.LOG_LOCAL4
		if(f=="LOG_LOCAL5"):
			return syslog.LOG_LOCAL5
		if(f=="LOG_LOCAL6"):
			return syslog.LOG_LOCAL6
		if(f=="LOG_LOCAL7"):
			return syslog.LOG_LOCAL7

	# convert string to priority!
	@staticmethod
	def str2priority(p):
		if(p=="LOG_ALERT"):
			return syslog.LOG_ALERT
		if(p=="LOG_CRIT"):
			return syslog.LOG_CRIT
		if(p=="LOG_DEBUG"):
			return syslog.LOG_DEBUG
		if(p=="LOG_EMERG"):
			return syslog.LOG_EMERG
		if(p=="LOG_ERR"):
			return syslog.LOG_ERR
		if(p=="LOG_INFO"):
			return syslog.LOG_INFO
		if(p=="LOG_NOTICE"):
			return syslog.LOG_NOTICE
		if(p=="LOG_WARNING"):
			return syslog.LOG_WARNING

	# convert tos value 2 dscp
	@staticmethod
	def tos2dscp(tos):
		if(tos < 32):
			return 0
		if(tos>=32 and tos<40):
			return 8
		if(tos>=40 and tos<48):
			return 10
		if(tos>=48 and tos<56):
			return 12
		if(tos>=56 and tos<64):
			return 14
		if(tos>=64 and tos<72):
			return 16
		if(tos>=72 and tos<80):
			return 18
		if(tos>=80 and tos<88):
			return 20
		if(tos>=88 and tos<96):
			return 22
		if(tos>=96 and tos<104):
			return 24
		if(tos>=104 and tos<112):
			return 26
		if(tos>=112 and tos<120):
			return 28
		if(tos>=120 and tos<128):
			return 30
		if(tos>=128 and tos<136):
			return 32
		if(tos>=136 and tos<144):
			return 34
		if(tos>=144 and tos<152):
			return 36
		if(tos>=152 and tos<160):
			return 38
		if(tos>=160 and tos<184):
			return 40
		if(tos>=184 and tos<192):
			return 46
		if(tos>=192 and tos<224):
			return 48
		if(tos>=224):
			return 56


class Collector:

	def __init__(self, params):
		self.time = params[0]
		self.path = params[1]+"/live/"+params[2]
		self.port = params[2]

	def checkPort(self):
		status, res = commands.getstatusoutput('netstat -nau --program | grep '+self.port)
		return status
	
	def runCollector(self):
		if self.checkPort() != 0: # Port is open
			print self.port + ' is Open'		
			if os.path.isdir(self.path)==False: # Create the directory to hold the collector's files
				print 'Creating the directory in '+self.path
				subprocess.call("mkdir "+self.path,shell=True)
			command = "nfcapd -w -t "+self.time+" -D -l "+self.path+" -p "+self.port
			print 'Launch the collector program: nfcapd'
			subprocess.call(command,shell=True) #Launch the collector program by exec the command
		else:
			print "Port "+self.port+" is used! Please change it"
			
class Processor:
	
	def __init__(self, params):
		self.time = params[0]
		self.path = params[1]+"/live/"+params[2]
		self.port = params[2]
		self.params = params

	def runProcessor(self):
		wm = pyinotify.WatchManager() # Watch Manager
		handler = EventHandler(params)
		notifier = pyinotify.Notifier(wm, handler)
		wdd = wm.add_watch(self.path, pyinotify.IN_MOVED_TO, rec=True)
		wm = pyinotify.WatchManager()
		try:
			self.checkpyinotifypid(self.path)
			#notifier.loop() #foreground
			notifier.loop(daemonize=True, pid_file=self.path+'/pyinotify.pid') #deamon process
		except pyinotify.NotifierError, err:
			print >> sys.stderr, err

	def checkpyinotifypid(self, path):
		if os.path.isdir(path):
			subprocess.call("rm -rf "+path+'/pyinotify.pid',shell=True)
		
		


class EventHandler(pyinotify.ProcessEvent):
	
	def __init__(self, params):
		self.timerotation = int(params[0]) #convert time from sec to msec
		self.path = params[1]+"/live/"+params[2]
		self.basedir = params[1]
		self.port = params[2]
		self.syslogserverlist = params[3]
		self.syslogpriority = params[4]
		self.syslogfacility = params[5]
		
		
	
	def process_IN_MOVED_TO(self, event):
		portList = ['']
		portList.append(self.port)
		d=pynfdump.Dumper(self.basedir, sources=portList)
		d.set_where(dirfiles="")
		records = pynfdump.search_file(event.pathname,"")
		self.logRecords(records,self.syslogserverlist,Util.str2facility(self.syslogfacility),Util.str2priority(self.syslogpriority),self.timerotation)
	
	def logRecords(self,records,syslogserverlist,syslogfacility,syslogpriority,timerotation):
		d = {}
		count = 0
		for r in records:
			l = []
			key = str(r['srcip']) + " " + str(r['srcport'])+ " " + str(r['dstip']) + " " + str(r['dstport']) 
			if not d.has_key(key):
				l.append(r['af'])
				l.append(r['first'])
				l.append(r['last'])
				l.append(r['prot'])
				l.append(r['srcip'])
				l.append(r['srcport'])
				l.append(r['dstip'])
				l.append(r['dstport'])
				l.append(r['srcas'])
				l.append(r['dstas'])
				l.append(r['input'])
				l.append(r['output'])
				l.append(r['flags'])
				l.append(r['tos'])
				l.append(Util.tos2dscp(r['tos']))
				l.append(r['packets'])
				l.append(r['bytes'])
				l.append(count)
				d[key] = l
			else:
				count += 1				
				if d.get(key)[1] > r['first']:
					d.get(key)[1] = r['first']
				if d.get(key)[2] < r['last']:
					d.get(key)[2] = r['last']
				d.get(key)[15] = d.get(key)[15] + r['packets']
				d.get(key)[16] = d.get(key)[16] + r['bytes']
				d.get(key)[17] = count #update the aggregation count
				
		for k in d.keys():
			d.get(k)[0]
			message = "af= "+ str(d.get(k)[0]) + " " + "first= "+ str(d.get(k)[1]) + " " + "last= "+ str(d.get(k)[2]) + " " + "proto= "+ str(d.get(k)[3]) + " " + "srcip= "+ str(d.get(k)[4]) + " " + "srcport= "+ str(d.get(k)[5])+ " " + "dstip= "+ str(d.get(k)[6]) + " " + "dstport= "+ str(d.get(k)[7]) + " " + "srcas= "+ str(d.get(k)[8]) + " " + "dstas= "+ str(d.get(k)[9])+ " " + "input= "+ str(d.get(k)[10]) + " " + "output= "+ str(d.get(k)[11]) + " " + "flags= "+ str(d.get(k)[12]) + " " + "tos= "+ str(d.get(k)[13])+ " " + "dscp= "+ str(d.get(k)[14]) + " " + "packets= "+ str(d.get(k)[15]) + " " + "bytes= "+ str(d.get(k)[16])+ " " + "aggregated= "+str(d.get(k)[17])+ " " + "timerotation= " + str(timerotation)
			logger = netsyslog.Logger()
			for syslogserver in syslogserverlist: 
					server = syslogserver.split(':') #syslogserver --> ip_address:UDP_port
					serverip = server[0] #ip address
					if len(server)>1: #if the user has specified the port in the config file
						logger.PORT = int(server[1]) #udp port
					else:
						logger.PORT = 514

					logger.add_host(serverip)
					logger.log(syslogfacility,syslogpriority, message, pid=True)


def worker(*params):
	try:
		#collect netflow
		collec = Collector(params)
		collec.runCollector()
		#process: read, aggregate, & send
		proc = Processor(params)
		proc.runProcessor()
	except SystemExit:
		os.system('sudo pkill nfcapd')




if __name__ == '__main__':
	
	parser = argparse.ArgumentParser(description='Script to collect, process, and send netflow data to syslog remote server(s)')
	#check if the user has privileges 	
	if os.getuid() == 0:
	#initialize the variables
		procs = []
		parser = SafeConfigParser()
		parser.read('Config.ini') #parse the config file
		
		for section in parser.sections():
			params = []
			params.append(parser.get(section, 'time'))
			params.append(parser.get(section, 'basedir'))
			params.append(parser.get(section, 'port'))
			params.append(parser.get(section, 'syslogserverlist').split(','))
			params.append(parser.get(section, 'syslogpriority'))
			params.append(parser.get(section, 'syslogfacility'))
			# Each process will get list of paramaters
			p = Process(target=worker,args=(params))
			procs.append(p)
			p.start()
	
	# wait for all worker processes to finish
		for p in procs:
			p.join()
	else:
		print("python: cannot run the script: You need root privileges.")
