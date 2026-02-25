#!/usr/bin/python3

########################################
#                                      #
#  Used to control Nessus through      #
#  scripting.                          #
#                                      #
#  Requires Python 3.x and requests    #
#  module                              #
#                                      #
#  Original Copyright (C) 2016         #
#  Matt Grandy                         #
#  Email: grandy[at]redteamsecure.com  #
#                                      #
#  Python 3 port - 2025                #
#                                      #
########################################

try:
	import requests
except ImportError:
	print('Need to install the Requests module before execution: pip install requests')
	exit()

import json
import sys
import argparse
import time
import configparser
import os
import re

# Disable Warning when not verifying SSL certs.
requests.packages.urllib3.disable_warnings()

# Create options and help menu
parser = argparse.ArgumentParser(description='Control Nessus with this script')
group = parser.add_mutually_exclusive_group()
group.add_argument('-l', '--list',    dest='scan_list',       action='store_true', help='List current scans and IDs')
group.add_argument('-p', '--policies',dest='policy_list',     action='store_true', help='List current policies')
group.add_argument('-sS', '--start',  dest='start_scan_id',   type=str,            help='Start a specified scan using scan id')
group.add_argument('-sR', '--resume', dest='resume_scan_id',  type=str,            help='Resume a specified scan using scan id')
group.add_argument('-pS', '--pause',  dest='pause_scan_id',   type=str,            help='Pause a specified scan using scan id')
group.add_argument('-sP', '--stop',   dest='stop_scan_id',    type=str,            help='Stop a specified scan using scan id')
parser.add_argument('-c', '--config', dest='config_file',     type=str,
					default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'autonessus.conf'),
					help='Path to config file (default: autonessus.conf in script directory)')

args = parser.parse_args()

if not len(sys.argv) > 1:
	parser.print_help()
	print()
	exit()

# Load configuration from file
def load_config(config_path):
	if not os.path.exists(config_path):
		print('Config file not found: {}'.format(config_path))
		print('Please create a config file with the following format:\n')
		print('  [autonessus]')
		print('  url = https://localhost:8834')
		print('  username = your_username')
		print('  password = your_password')
		print('  verify_ssl = false\n')
		print('Tip: Run "chmod 600 {}" to restrict access to the file.'.format(config_path))
		exit()

	config = configparser.ConfigParser()
	config.read(config_path)

	if 'autonessus' not in config:
		print('Config file is missing the [autonessus] section: {}'.format(config_path))
		exit()

	section = config['autonessus']
	required_keys = ['url', 'username', 'password']
	for key in required_keys:
		if key not in section or not section[key].strip():
			print('Config file is missing required field: {}'.format(key))
			exit()

	return {
		'url':      section.get('url',        'https://localhost:8834').rstrip('/'),
		'username': section.get('username'),
		'password': section.get('password'),
		'verify':   section.getboolean('verify_ssl', fallback=False),
	}

cfg      = load_config(args.config_file)
url      = cfg['url']
verify   = cfg['verify']
token    = ''
api_token = ''
username = cfg['username']
password = cfg['password']


def get_api_token():
	"""Fetch and extract the X-API-Token from nessus6.js.

	Nessus Professional requires this token in addition to the session cookie
	for scan control endpoints (launch, pause, resume, stop). It is embedded
	as a UUID inside the nessus6.js file served by the Nessus web UI.
	"""
	try:
		r = requests.get(
			'{}/nessus6.js'.format(url),
			headers={'X-Cookie': 'token={}'.format(token)},
			verify=verify
		)
		match = re.search(
			r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
			r.text,
			re.IGNORECASE
		)
		if match:
			return match.group(1)
	except Exception as e:
		print('Warning: could not retrieve X-API-Token from nessus6.js: {}'.format(e))
	return None


# Column widths for tabular output
COL_NAME   = 50
COL_STATUS = 16
COL_ID     = 10
COL_UUID   = 40

def truncate(text, width):
	"""Truncate text to fit within width, appending '...' if needed."""
	if len(text) <= width:
		return text.ljust(width)
	return text[:width - 3] + '...'

def print_scan_header():
	"""Print the header row for scan listings."""
	print('{}  {}  {}'.format(
		'Scan Name'.ljust(COL_NAME),
		'Status'.ljust(COL_STATUS),
		'ID'
	))
	print('-' * (COL_NAME + COL_STATUS + COL_ID + 16))

def print_scan_row(name, status, scan_id):
	"""Print a single scan row with aligned columns."""
	print('{}  {}  {}'.format(
		truncate(name, COL_NAME),
		status.ljust(COL_STATUS),
		str(scan_id)
	))

def print_policy_header():
	"""Print the header row for policy listings."""
	print('{}  {}'.format(
		'Policy Name'.ljust(COL_NAME),
		'UUID'
	))
	print('-' * (COL_NAME + COL_UUID + 8))

def print_policy_row(name, uuid):
	"""Print a single policy row with aligned columns."""
	print('{}  {}'.format(
		truncate(name, COL_NAME),
		uuid
	))

def print_status_header():
	"""Print the header row for single-scan status output."""
	print('\n{}  {}'.format(
		'Scan Name'.ljust(COL_NAME),
		'Status'
	))
	print('-' * (COL_NAME + COL_STATUS + 8))

def print_status_row(name, status):
	"""Print a single scan status row."""
	print('{}  {}'.format(
		truncate(name, COL_NAME),
		status
	))

def build_url(resource):
	return '{0}{1}'.format(url, resource)


def connect(method, resource, data=None, params=None):
	"""
	Send a request

	Send a request to Nessus based on the specified data. If the session token
	is available add it to the request. Specify the content type as JSON and
	convert the data to JSON format.
	"""
	headers = {
		'X-Cookie': 'token={0}'.format(token),
		'X-API-Token': api_token,
		'content-type': 'application/json'
	}

	data = json.dumps(data) if data is not None else None

	if method == 'POST':
		r = requests.post(build_url(resource),   data=data, headers=headers, verify=verify)
	elif method == 'PUT':
		r = requests.put(build_url(resource),    data=data, headers=headers, verify=verify)
	elif method == 'DELETE':
		r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
	else:
		r = requests.get(build_url(resource), params=params, headers=headers, verify=verify)

	# Exit if there is an error.
	if r.status_code != 200:
		try:
			e = r.json()
			error_msg = e.get('error', 'Unknown error')
		except Exception:
			error_msg = 'HTTP {}'.format(r.status_code)

		if error_msg == 'API is not available':
			print('Error: Nessus returned "API is not available".')
			print('Nessus Professional restricts scan control (launch/pause/resume/stop) via API.')
			print('These operations must be performed through the Nessus web UI, or by upgrading')
			print('to Nessus Expert or using the Tenable.io cloud API.')
		else:
			print('Error: {}'.format(error_msg))
		sys.exit()

	# When downloading a scan we need the raw contents not the JSON data.
	if 'download' in resource:
		return r.content

	# All other responses should be JSON data. Return raw content if they are not.
	try:
		return r.json()
	except (ValueError, requests.exceptions.JSONDecodeError):
		return r.content


def login(usr, pwd):
	"""Login to Nessus."""
	login_data = {'username': usr, 'password': pwd}
	data = connect('POST', '/session', data=login_data)
	return data['token']


def get_policies():
	"""
	Get scan policies.
	Get all of the scan policies but return only the title and the uuid of
	each policy.
	"""
	data = connect('GET', '/editor/policy/templates')
	return {p['title']: p['uuid'] for p in data['templates']}


def get_scans():
	"""
	Get scans.
	Create dictionaries mapping scan id -> status and scan id -> name.
	"""
	status_dict = {}
	name_dict   = {}
	data = connect('GET', '/scans/')
	for p in data['scans']:
		status_dict[p['id']] = p['status']
		name_dict[p['id']]   = p['name']
	return status_dict, name_dict


def get_history_ids(sid):
	"""
	Get history ids.
	Create a dictionary of scan uuids and history ids so we can look up the
	history id by uuid.
	"""
	data = connect('GET', '/scans/{0}'.format(sid))
	temp_hist_dict     = {h['history_id']: h['status'] for h in data['history']}
	temp_hist_dict_rev = {v: k for k, v in temp_hist_dict.items()}
	try:
		for key, value in temp_hist_dict_rev.items():
			print(key)
			print(value)
	except Exception:
		pass


def get_scan_history(sid, hid):
	"""
	Scan history details.
	Get the details of a particular run of a scan.
	"""
	params = {'history_id': hid}
	data = connect('GET', '/scans/{0}'.format(sid), params)
	return data['info']


def get_status(sid):
	"""Get the status of a scan by the sid and print it."""
	time.sleep(3)  # sleep to allow Nessus to process the previous status change
	temp_status_dict, temp_name_dict = get_scans()
	print_status_header()
	for key, value in temp_name_dict.items():
		if str(key) == str(sid):
			print_status_row(value, temp_status_dict[key])


def launch(sid):
	"""Launch the scan specified by the sid.

	Nessus frequently resets the connection immediately after processing a
	launch request, before sending a response. This is a known Nessus
	behaviour and does not mean the launch failed. We catch the error,
	wait for Nessus to transition the scan state, and poll the status
	a few times to confirm.
	"""
	try:
		data = connect('POST', '/scans/{0}/launch'.format(sid))
		return data.get('scan_uuid')
	except requests.exceptions.ConnectionError:
		pass  # Expected -- Nessus drops the connection after processing

	# Poll up to 5 times over 15 seconds for the scan to transition state
	print('Waiting for Nessus to update scan state...')
	for attempt in range(5):
		time.sleep(3)
		status_dict, _ = get_scans()
		scan_status = status_dict.get(int(sid))
		if scan_status and scan_status.lower() in ['running', 'pending', 'initializing']:
			return None  # Launch confirmed
		print('  Status check {}/5: {}'.format(attempt + 1, scan_status))

	# Final status after all polls
	status_dict, _ = get_scans()
	scan_status = status_dict.get(int(sid))
	if scan_status and scan_status.lower() not in ['empty', 'completed', 'stopped', 'aborted', 'canceled']:
		return None  # Some transitional state -- probably fine
	print('Error: scan {} did not start (final status: {}).'.format(sid, scan_status))
	logout()


def pause(sid):
	"""Pause the scan specified by the sid."""
	connect('POST', '/scans/{0}/pause'.format(sid))


def resume(sid):
	"""Resume the scan specified by the sid."""
	connect('POST', '/scans/{0}/resume'.format(sid))


def stop(sid):
	"""Stop the scan specified by the sid."""
	connect('POST', '/scans/{0}/stop'.format(sid))


def logout():
	"""Logout of Nessus."""
	print('Logging Out...')
	headers = {
		'X-Cookie': 'token={0}'.format(token),
		'X-API-Token': api_token,
		'content-type': 'application/json'
	}
	requests.delete(build_url('/session'), headers=headers, verify=verify)
	print('Logged Out')
	exit()


if __name__ == '__main__':
	print('Script started: ' + time.strftime('%m-%d-%y @ %H:%M:%S'))

	print('Logging in...')
	try:
		token = login(username, password)
	except Exception:
		print('Unable to login :(')
		exit()
	print('Logged in!')

	# Fetch the X-API-Token required for scan control on Nessus Professional
	api_token = get_api_token()
	if not api_token:
		print('Warning: could not retrieve X-API-Token. Scan control operations may fail.')
	else:
		print('API token retrieved.')



	###### Display all policies ######
	if args.policy_list:
		print('\nPolicies\n')
		policy_dict = get_policies()
		print_policy_header()
		for title, uuid in policy_dict.items():
			print_policy_row(title, uuid)


	###### Display all scans ######
	elif args.scan_list:
		temp_status_dict, temp_name_dict = get_scans()
		print_scan_header()
		for scan_id, name in temp_name_dict.items():
			print_scan_row(name, temp_status_dict[scan_id], scan_id)


	###### Start the scan ######
	if args.start_scan_id:
		start_id = args.start_scan_id
		temp_status_dict, temp_name_dict = get_scans()

		for key, value in temp_name_dict.items():
			if str(key) == str(start_id):
				scan_status = temp_status_dict[key].lower()
				if scan_status in ['stopped', 'completed', 'aborted', 'canceled', 'on demand', 'empty']:
					print('Launching Scan {}'.format(key))
					launch(start_id)
				elif scan_status == 'running':
					print('Scan already running!')
					logout()
				else:
					print('Scan already started or paused.')
					print('If you need to start a previously completed scan, add "completed" to the allowed statuses list.')
					logout()

		get_status(start_id)


	###### Resume the scan ######
	if args.resume_scan_id:
		start_id = args.resume_scan_id
		temp_status_dict, temp_name_dict = get_scans()

		for key, value in temp_name_dict.items():
			if str(key) == str(start_id):
				scan_status = temp_status_dict[key].lower()
				if scan_status == 'paused':
					print('Resuming Scan {}'.format(key))
					resume(start_id)
				elif scan_status == 'running':
					print('Scan already running!')
					logout()
				else:
					print('Scan unable to start.')
					logout()

		get_status(start_id)


	###### Pause the scan ######
	elif args.pause_scan_id:
		pause_id = args.pause_scan_id
		temp_status_dict, temp_name_dict = get_scans()

		for key, value in temp_name_dict.items():
			if str(key) == str(pause_id):
				scan_status = temp_status_dict[key].lower()
				if scan_status == 'paused':
					print('Scan already paused!')
					logout()
				elif scan_status == 'running':
					print('Pausing Scan {}'.format(key))
					pause(pause_id)
				else:
					print('Scan unable to be paused')
					logout()

		get_status(pause_id)


	###### Stop the scan ######
	elif args.stop_scan_id:
		stop_id = args.stop_scan_id
		temp_status_dict, temp_name_dict = get_scans()

		for key, value in temp_name_dict.items():
			if str(key) == str(stop_id):
				scan_status = temp_status_dict[key].lower()
				if scan_status in ['paused', 'running']:
					print('Stopping Scan {}'.format(key))
					stop(stop_id)
					logout()
				else:
					print('Scan cannot be stopped!')
					logout()

		get_status(stop_id)

	logout()
