#!/usr/bin/env python2.7
# -*- coding: UTF-8 -*-


#####################################################
# Documentation!
#####################################################
__doc__ = info = '''
A small script receiving JSON commands and logging out OS X users if requested.
'''
__author__ = "Kai Ellinger"
__copyright__ = "Copyright 2015, Kai Ellinger"
#__credits__ = ["yes", "please"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Kai Ellinger"
__email__ = "coding@blicke.de"
__status__ = "Development"


#####################################################
# Imports!
#####################################################
# used modules
import os, sys
import ConfigParser # reading user configuration
import argparse     # reading user arguments
import traceback    # printing stack trace
import logging      # for logging text
if not sys.platform.startswith('win'):
	from logging.handlers import SysLogHandler # SYSLOG logging
	import socket # accessing hostname for SYSLOG filter
	import pwd    # log user name in SYSLOG
# LOGOUTD specific
# pip install flask PyObjC
from flask import Flask, request, jsonify, abort
app = Flask(__name__)


#####################################################
# Infrastructure to be reused in other scripts!
#####################################################
# DEBUG
# - even higher log levels ignore debug messages
#   there might be a performance reasons for checking
#   whether code needs to be executed at all if no debug
#   message will be printed
is_debug   = False

# Printing stack trace
def print_stack(stack_trace=None):
	if __debug__:
		'''
		This function is used for debugging only.
		'''
		# TODO - How to print a stack trace from an exception via this method?
		global is_debug
		stack_trace = None
		if stack_trace is None:
			# - logging.debug("text",exc_info=True) does not work
			# See: https://bugs.python.org/issue9427
			stack_trace = traceback.format_stack()
			stack_trace.pop()

		# create both strings only once and reuse them
		if not hasattr(print_stack, "BEGIN"):
			print_stack.BEGIN = ' '.join( ["-" * 20, "BEGIN: STACKTRACE", "-" * 20, u'\n++%s'] )
			print_stack.END   = ' '.join( ["-" * 20, "END:   STACKTRACE", "-" * 20] )
		logging.debug( print_stack.BEGIN % (u'++'.join( stack_trace )) )
		logging.debug( print_stack.END )

# Read command line arguments
def parse_arguments(syslogAppName='PYTHON',syslogFacility=SysLogHandler.LOG_USER):
	global is_debug
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('-v','--version', action='version', version="%(prog)s ("+__version__+")" )
	# if not calling python with -O option
	# ORDER - having parameter INFO and DEBUG sets log level to DEBUG
	parser.add_argument('-I','--INFO', action='store_const', dest='LOGLEVEL', const=logging.INFO, help='log level set to INFO')
	# calling python with -O option disables debug information
	if __debug__:
		parser.add_argument('-D','--DEBUG', action='store_const', dest='LOGLEVEL', const=logging.DEBUG, help='log level set to DEBUG')
	parser.add_argument('-L','--logfile', type=str, dest='LOGFILE', help='use a log file instead of STDOUT' )
	# its win32, maybe there is win64 too?
	if not sys.platform.startswith('win'):
		parser.add_argument('-S','--syslog', action='store_true', default=False, dest='LOGSYSLOG', help='also log to syslog in addition to STDOUT or log files' )
	# method call to add business logic specific arguments
	add_business_logic_arguments(parser)
	args = parser.parse_args()

	# setup logging as soon as possible to have it ready when needed
	if not setup_logging(args, syslogAppName, syslogFacility):
		args.ERROR_SETUPLOG = True

	# is the config file readable?
	logging.debug("CONFIG file: %s" % args.CONFIG )
	if not os.path.isfile(args.CONFIG) or not os.access( args.CONFIG, os.R_OK ):
		logging.info("Can NOT access file '%s'! Continue without!" % args.CONFIG )
		#logging.error("Can NOT access file '%s'!" % args.CONFIG )
		#if is_debug: print_stack() # just to test the method
		#args.ERROR_READCONFIG = True
	else:
		if not read_config( args.CONFIG, args ):
			args.ERROR_READCONFIG = True
	return args

# Configure logging according to command line options
def setup_logging(args, syslogAppName, syslogFacility):
	# setting log format
	# See: https://docs.python.org/2/library/logging.html#logrecord-attributes
	if logging.DEBUG == args.LOGLEVEL:
		logging_format_string = '%(asctime)s [%(levelname)-7s][%(pathname)s][%(filename)s:%(lineno)04d][%(funcName)s] %(message)s'
	else:
		logging_format_string = '%(asctime)s [%(levelname)-7s][%(filename)s:%(lineno)04d][%(funcName)s] %(message)s'
	# finish setting log level
	if not hasattr(args, 'LOGLEVEL') or args.LOGLEVEL is None:
		args.LOGLEVEL = logging.WARNING
	if args.LOGLEVEL == logging.DEBUG:
		is_debug = True
	# log destination selection
	write_to_log = False
	log_file_error_msg = None
	if hasattr(args, 'LOGFILE') and args.LOGFILE is not None:
		# append existing log
		if os.path.isfile( args.LOGFILE ):
			# if existing file is writable; use it
			write_to_log = os.access( args.LOGFILE, os.W_OK )
			if not write_to_log:
				log_file_error_msg = "LOG: File '%s' exists but is not writable! Using STDOUT!" % args.LOGFILE
		# log file does not yet exist
		else:
			log_dir = os.path.dirname( args.LOGFILE )
			# if args.LOGFILE does not contain a directory name
			if '' == log_dir:
				log_dir = '.'
			# check dir permissions
			write_to_log = os.access(log_dir, os.W_OK | os.X_OK)
			if not write_to_log:
				log_file_error_msg = "LOG: Directory '%s' is not writable! Using STDOUT!" % log_dir

	# writing to STDOUT or to file?
	if write_to_log:
		logging.basicConfig(filename=args.LOGFILE, format=logging_format_string, level=args.LOGLEVEL)
	else:
		logging.basicConfig(format=logging_format_string, level=args.LOGLEVEL)
		if log_file_error_msg is not None:
			logging.warn(log_file_error_msg)

	# create additional SYSLOG logger if requested
	if hasattr(args, 'LOGSYSLOG') and args.LOGSYSLOG:
		# See: https://docs.python.org/2/library/logging.handlers.html#sysloghandler

		# Helper class for user specific fields in SYSLOG
		# Implements:
		#   %(hostname)s - the host name of the computer this scripts runs on
		#   %(username)s - the user name running the scripts runs with
		#   %(logname)s  - name to be written to SYSLOG
		class ContextFilter(logging.Filter):
			hostname = socket.gethostname()
			username = pwd.getpwuid(os.getuid())[0]
			appname  = syslogAppName

			def filter(self, record):
				record.hostname = ContextFilter.hostname
				record.username = ContextFilter.username
				record.appname = ContextFilter.appname
				return True
		
		# See: https://docs.python.org/2/library/sys.html#sys.platform
		syslog_socket = None
		if sys.platform.startswith('linux'):
			# linux
			syslog_socket = '/dev/log'
		elif sys.platform.startswith('darwin'):
			# OS X
			syslog_socket = '/var/run/syslog'
		else:
			# - might be BSD or CYGWIN
			# - Windows: This code will not be executed on Windows
			#            because no --syslog option is available
			logging.error("SYSLOG logging not yet supported for this platform '%s'!" % sys.platform )
			return False

		# Add SYSLOG logger
		syslog_format_string = '%(asctime)s %(appname)s[%(process)d]: [%(levelname)s][%(username)s][%(filename)s:%(lineno)04d][%(funcName)s] %(message)s'
		rootLogger = logging.getLogger()
		rootLogger.setLevel(args.LOGLEVEL)
		syslogFilter = ContextFilter()
		rootLogger.addFilter(syslogFilter)
		syslog = SysLogHandler(address=syslog_socket, facility=syslogFacility  )
		syslogFormatter = logging.Formatter(syslog_format_string, datefmt='%b %d %H:%M:%S')
		syslog.setFormatter(syslogFormatter)
		rootLogger.addHandler(syslog)

	return True


#####################################################
# Business logic dedicated to this script!
#####################################################
# Adds project specific command line arguments
def add_business_logic_arguments(parser):
	global is_debug
	parser.add_argument('-C','--config', type=str, dest='CONFIG', default="%s/%s" % ( os.environ['HOME'] , '.logoutrc' ), help='LOGOUTD config file' )
	parser.add_argument('-A','--accesslog', type=str, dest='ACCESSLOG', default="%s/%s" % ( os.environ['HOME'] , '.logoutdACCESSLOG' ), help='ACCESSLOG file for LOGOUD' )
	parser.add_argument('-LP','--listen-port', type=int, dest='LISTENPORT', default=8083, help='Listen port (default 8083)' )
	parser.add_argument('-LI','--listen-ip', type=str, dest='LISTENIP', default="127.0.0.1", help='Listen IP (default 127.0.0.1)' )

# Read LOGOUTD config file!
def read_config(config_file, args):
	global is_debug
	# pop3_server = pop3_username = pop3_password = None
	# config = ConfigParser.ConfigParser()
	# config.read( config_file )

	# if config.has_section("retriever"):
	# 	if config.has_option("retriever", "type"):
	# 		if "MultidropPOP3SSLRetriever" == config.get("retriever", "type"):
	# 			if config.has_option("retriever", "server"):
	# 				args.pop3_server = config.get("retriever", "server")
	# 			if config.has_option("retriever", "username"):
	# 				args.pop3_username = config.get("retriever", "username")
	# 			if config.has_option("retriever", "password"):
	# 				args.pop3_password = config.get("retriever", "password")
	# 		else:
	# 			logging.error("the current version supports 'type=MultidropPOP3SSLRetriever' only!")
	# 			return False
	# else:
	# 	logging.error("no section [retriever] found!")
	# 	return False

	return True

#
@app.route('/edward/api/v1.0/status', methods=['POST'])
def get_tasks():
	if not request.json or not 'user' in request.json:
		abort(400)

	user = [
		{
			'user': request.json['user'],
			'logintime': u'30 Min',
			'active': True
		}
	]
	return jsonify({'user': user})


# MAIN method
def main():
	global is_debug
	# checking command line arguments
	args = parse_arguments(syslogAppName="POP3MONITOR",syslogFacility=SysLogHandler.LOG_MAIL)
	if args is None:
		logging.debug("ARGS is None")
		return -22
	elif hasattr(args, 'ERROR_SETUPLOG') and args.ERROR_SETUPLOG:
		logging.debug("ARGS has ERROR_SETUPLOG")
		return -33
	elif hasattr(args, 'ERROR_READCONFIG') and args.ERROR_READCONFIG:
		logging.debug("ARGS has ERROR_READCONFIG")
		return -44
	logging.debug("ARGS is fine!")

	logging.debug("Starting web server!")

	app.run(host=args.LISTENIP,port=args.LISTENPORT,debug=is_debug)
	return listen(args)

# only call MAIN method if directly called!
if __name__ == '__main__':
	sys.exit(main())

# vim: set tabstop=4 softtabstop=4 shiftwidth=4 noexpandtab number syntax=python foldmethod=indent nofoldenable :
