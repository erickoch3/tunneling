#!/usr/bin/env python3

import os
import pexpect
import re
import sys

#####
#		The following script is used to create a dynamic tunnel through port 9050
#		that can be accessed via proxychains. The tunnel is created via local and
#		remote port forwarding commands run using the pexpect module. Many of the
#		artifacts in the code are vestiges of a reconnaissance crawler still in
#		development. Aiming to eventually upgrade into a GUI.
#####

### A Global class to maintain global variables that need to be referenced.
class Glob:
	device_dictionary = dict() # A dictionary mapping ip strings to device objects
	hosts = set() # A set of all hosts initialized

### The Device class is any network device
class Device:
	def __init__(self, ip):
		self.ip = ip
		self.hostname = "hostname unknown"
		self.note = ""
		self.public_ip = self.ip
		self.private_ip = self.ip
		self.ip_interfaces = {}
		self.ip_addresses = {self.ip}
		self.connection_successful = False

	### Attempt ssh_connection to this device
	def ssh_connection(self, username, password, proc=None):
		"""
		Args: IP, username, password
		Returns: a running pexpect process handling an ssh connection with the designated IP.
		"""
		if debug: print("Attempting connection...")
		ssh_cmd = "ssh " + username + "@" + self.ip
		try:
			if debug: print("Sending command: ", ssh_cmd)
			if proc==None:
				proc = pexpect.spawn(ssh_cmd)
			else:
				proc.sendline(ssh_cmd)
			proc.expect("password:", timeout = 1)
			proc.sendline(password)
			proc.expect("\$", timeout = 1)
			if debug: print("Connection succesful.")
			self.connection_successful = True
			# Determine device hostname
			hostname_regex = r'\@([a-zA-z0-9\-\_]+)\:'
			self.hostname= self.send_command(proc, 'hostname', hostname_regex)[0]
			return proc
		except:
			if debug: print("Connection failed.")
			self.note = 'Failed to authenticate.'
			proc.sendcontrol('c')
			proc.expect(pexpect.EOF)
			raise Exception("Login Failed.")

	### Sends a command using pexpect given a process and regex pattern to read
	### the response.
	def send_command(self, proc, command, regex1, regex2=False):
		"""
		Args: running ssh process, command to run, regex to parse the response, optional additional regex
		Returns: the response of the system parsed via the input regex, response parsed by optional regex
		"""
		if debug: print("Attempting command: ", command)
		proc.sendline(command)
		proc.expect("\$", timeout = 1)
		response = proc.before.decode('utf-8')
		if debug: print("Returning command response!")
		if regex2:
			return re.findall(regex1, response), re.findall(regex2, response)
		else:
			return re.findall(regex1, response)

### A Host class to contain reference to ssh and telnet usernames and passwords.
### Initializes the host device into the global device dictioanry.
class Host(Device):

	def __init__(self, ip, gateway=None):
		if debug: print("Attempting to initialize host: ", ip)
		Device.__init__(self, ip)
		self.type = "Computer Host"
		self.gateway = gateway
		self.open_ports = dict()
		Glob.device_dictionary[self.ip] = self
		Glob.hosts.add(self)
		self.ssh_blocked = set()
		self.ssh_port = 22
		self.telnet_port = 23
		self.username = None
		self.password = None
		self.telnet_username = None
		self.telnet_password = None

def request_devices():
	"""
	Args: None, receives ip's to tunnel to via user input.
	Returns: Device list to be used for building a tunnel
	"""
	print("Please input the machines through which we will tunnel.")
	print("Format: IP, ssh port, telnet port, username, password, wall before?")
	print("wall before = y/n. Don't use spaces!")
	print("Start with your own device. Type 'help' for more info:")
	usr_inp = input()
	if usr_inp.lower() == 'help':
		print("\n'Wall before' means that a firewall is preventing ssh connection")
		print("to this device, but telnet connection is possible. If you can't")
		print("Telnet or ssh, you're out of luck... Input the public IP's here.")
		print("After you input these IP's, you will have the opportunity to input")
		print("mappings between public and private IP's as well as the starting")
		print("rport. Go ahead and begin inputting IP's:")
		usr_inp = input()
	devices = []
	while usr_inp.lower() != 'stop':
		# Check format and parse the information given
		try:
			ip, ssh_port, telnet_port, username, password, wall_before = usr_inp.split(',')
			if debug: print("Creating new host...")
			device = Host(ip)
			device.username = username
			device.password = password
			device.ssh_port = ssh_port
			device.telnet_port = telnet_port
			if wall_before == 'y':
				device.ssh_blocked.add(devices[-1].ip)
			devices.append(device)
		except:
			print("Something's wrong... Make sure to input the right format!")
			sys.exit()
		# Next device info
		print("Enter next device info or 'stop':")
		usr_inp = input()
	print("Please input any telnet username, passwords in the form--")
	print("ip,telnet_username,telnet_password and then type 'done':")
	user_inp = input()
	while user_inp.lower() != 'done':
		try:
			ip,telnet_username,telnet_password = user_inp.split(',')
			device = Glob.device_dictionary[ip]
			device.telnet_username,device.telnet_password = telnet_username,telnet_password
		except:
			print("Something's wrong... Make sure to input the right format!")
			sys.exit()
		print("Please input next telnet mapping or 'done':")
		user_inp = input()
	print("Please input a starting tunnel port:")
	rport = int(input())
	print("If any devices possesses a private ip, please add the mapping in the")
	print("form- 'public_ip,private_ip'. When complete, type 'done'. Go ahead:")
	ip_mapping = input()
	while ip_mapping.lower() != 'done':
		try:
			public,private = ip_mapping.split(',')
			device = Glob.device_dictionary[public]
			device.private_ip = private
			Glob.device_dictionary[private] = device
		except:
			print("Something's wrong... Make sure to input the right format!")
			sys.exit()
		print("Please input next public/private ip mapping or 'done':")
		ip_mapping = input()
	return devices, rport

def add_telnet_cmd_and_credentials(cmd_list,cmd,device,num):
	"""
	Args: command list holding commands to run, a telnet cmd to add, a device
		to target, and the number of the command.
	Returns: an updated command list
	"""
	cmd_list.append([num,cmd])
	cmd_list.append([num,device.telnet_username])
	cmd_list.append([num,device.telnet_password])
	return cmd_list

def add_ssh_cmd_and_credentials(cmd_list,cmd,device,num):
	"""
	Args: command list holding commands to run, an ssh cmd to add, a device
		to target, and the number of the command.
	Returns: an updated command list
	"""
	cmd_list.append([num,cmd])
	cmd_list.append([num,device.password])
	return cmd_list

def make_LPF_cmd(ssh_device,target_device,in_port,local_ssh,local_target,type,active_ssh_port,alt_out_port=None):
	"""
	Args:
		ssh_device: the ssh device to be used to initiate the local port forwarding
		target_device: the device to forward to
		in_port (str): the port on the ssh_device that will open the tunnel
		local_ssh (Bool): True/False whether we are ssh'ing into the local device
		local_target (Bool): True/False whether our target_device is the ssh_device
		type (str): telnet, push, or ssh. Telnet opens a tunnel to telnet port,
			ssh opens a tunnel to the ssh port, and push redirects between two other ports
		active_ssh_port (str): the port that is used to access the ssh device
		alt_out_port (int, optional): an alternate out port to use if type push
	Returns: an LPF command
	"""
	cmd = "ssh " + ssh_device.username + "@"
	if local_ssh == True:
		cmd += "localhost"
	else:
		cmd += ssh_device.ip
	cmd += " -L " + in_port + ":"
	if local_target == True:
		cmd += "localhost:"
	else:
		cmd += target_device.ip + ":"
	if type == 'telnet':
		cmd += target_device.telnet_port
	elif type == 'push':
		cmd += alt_out_port
	else:
		cmd += target_device.ssh_port
	cmd += " -p " + active_ssh_port
	return cmd

def make_RPF_cmd(ssh_device,target_device,in_port,local,type):
	"""
	Args:
		ssh_device: the ssh device to be used to initiate the local port forwarding
		target_device: the device to forward to
		in_port (str): the port on the ssh_device that will open the tunnel
		local (Bool): True/False whether our target_device is the ssh_device
		type (str): telnet, or ssh. Telnet opens a tunnel to telnet port,
			ssh opens a tunnel to the ssh port.
	Returns: an RPF command
	"""
	cmd = "ssh " + ssh_device.username + "@" + ssh_device.private_ip + " -R " + in_port + ":"
	if local == True:
		cmd += "localhost:" + target_device.ssh_port
	elif type == 'telnet':
		cmd += target_device.ip + ":" + target_device.telnet_port
	else:
		cmd += target_device.ip + ":" + target_device.ssh_port
	cmd += " -p " + ssh_device.ssh_port
	return cmd

def generate_commands(devices, rport):
	"""
	Args: list of devices starting with own, ending with desired tunnel endpoint
			a random port to start the tunnel with
	Returns: a list of commands to create an ssh tunnel
	"""
	prev_telnet = False
	just_RPFd = False
	cmd_list = []
	index = 1
	num = 1
	curr_rport = str(rport)
	for device in devices[1:]:

		curr_rport = str( int(curr_rport) + 1 )
		prev_device = devices[index-1]
		facing_wall = False

		if index == len(devices)-1:
			next_device = None
		else:
			next_device = devices[index+1]
			if device.ip in next_device.ssh_blocked: facing_wall = True

		if prev_device.ip in device.ssh_blocked:
			if debug: print("We're making an RPF connection to ", device.ip)

			# Add a command to telnet in!
			if index == 1:
				telnet_cmd = "telnet " + device.ip + " " + device.telnet_port
				prev_ssh_dev, prev_ssh_port = devices[0], curr_rport
			else:
				telnet_cmd = "telnet localhost " + telnet_rport
			cmd_list = add_telnet_cmd_and_credentials(cmd_list,telnet_cmd,device,num)

			# If last, send the tunnel to the target's local host.
			if index == len(devices)-1:
				RPF_cmd = make_RPF_cmd(prev_ssh_dev,device,curr_rport,True,'ssh')
				cmd_list = add_ssh_cmd_and_credentials(cmd_list,RPF_cmd,prev_ssh_dev,num)
				if index != 1:
					num += 1
					# If not the first device, we need to tunnel the RPF back onto the local device
					prev_rport, curr_rport = curr_rport, str(int(curr_rport) + 1)
					LPF_cmd = make_LPF_cmd(prev_ssh_dev,None,curr_rport,True,True,'push',prev_ssh_port,prev_rport)
					cmd_list = add_ssh_cmd_and_credentials(cmd_list,LPF_cmd,prev_ssh_dev,num)
			# Otherwise, send the tunnel to the next ip.
			else:
				temp_prev_ssh_port = prev_ssh_port
				temp_prev_ssh_dev = prev_ssh_dev
				# If the next device is telnet only, we're not going to forward
				if device.ip in next_device.ssh_blocked:
					target_device = device
					local = True
				else:
					target_device = next_device
					local = False
				# Add SSH RPF, and forward it to attack box if already telneted.
				RPF_cmd = make_RPF_cmd(prev_ssh_dev,target_device,curr_rport,local,'ssh')
				cmd_list = add_ssh_cmd_and_credentials(cmd_list,RPF_cmd,prev_ssh_dev,num)
				if index != 1:
					num += 1
					prev_rport, curr_rport = curr_rport, str(int(curr_rport) + 1)
					LPF_cmd = make_LPF_cmd(prev_ssh_dev,None,curr_rport,True,True,'push',temp_prev_ssh_port,prev_rport)
					cmd_list = add_ssh_cmd_and_credentials(cmd_list,LPF_cmd,prev_ssh_dev,num)
				prev_ssh_port = curr_rport
				prev_ssh_dev = target_device
				# If the next device is also going to block ssh,
				# we will also create both telnet RPF
				if device.ip in next_device.ssh_blocked:
					curr_rport = str(int(curr_rport) + 1)
					cmd_list = add_telnet_cmd_and_credentials(cmd_list,telnet_cmd,device,num)
					RPF_cmd = make_RPF_cmd(temp_prev_ssh_dev,next_device,curr_rport,False,'telnet')
					cmd_list = add_ssh_cmd_and_credentials(cmd_list,RPF_cmd,prev_ssh_dev,num)
					if index != 1:
						num += 1
						prev_rport, curr_rport = curr_rport, str(int(curr_rport) + 1)
						LPF_cmd = make_LPF_cmd(prev_ssh_dev,None,curr_rport,True,True,'push',temp_prev_ssh_port,prev_rport)
						cmd_list = add_ssh_cmd_and_credentials(cmd_list,LPF_cmd,prev_ssh_dev,num)
					telnet_rport = curr_rport
					prev_ssh_dev = device

				prev_telnet = True
				just_RPFd = True

		# Regular local port forwarding
		else:
			### Set up the basic information regarding an LPF command
			# After the first device, we're always going to ssh into localhost
			target_device = device if (index == len(devices)-1) else next_device
			local_ssh = False if (index == 1) else True
			# If we just finished an RPF or are on the last device, we don't try to
			# Target the next device
			if index != len(devices)-1 or just_RPFd == True:
				local_target = False
			else:
				local_target = True
			# After the first device, we will have a running ssh port on localhost
			# That redirects us to the current machine at the end of the tunnel.
			active_ssh_port = device.ssh_port if (index == 1) else prev_ssh_port

			if not facing_wall:
				# Make an LPF command
				LPF_cmd = make_LPF_cmd(device,target_device,curr_rport,local_ssh,local_target,'ssh',active_ssh_port)
				prev_ssh_dev = target_device
				prev_ssh_port = curr_rport
			if facing_wall:
				# Make an LPF command to the local device's ssh port AND
				# the next device's telnet port.
				if index == 1:
					# Make the ssh LPF
					LPF_cmd = make_LPF_cmd(device,device,curr_rport,local_ssh,True,'ssh',active_ssh_port)
					cmd_list = add_ssh_cmd_and_credentials(cmd_list,LPF_cmd,device,num)
					prev_ssh_dev = device
					prev_ssh_port = curr_rport
					curr_rport = str(int(curr_rport)+1)
					num += 1
				# Make the telnet LPF
				LPF_cmd = make_LPF_cmd(device,target_device,curr_rport,local_ssh,local_target,'telnet',active_ssh_port)
				telnet_rport = curr_rport
			cmd_list = add_ssh_cmd_and_credentials(cmd_list,LPF_cmd,device,num)
			just_RPFd = False
		# Increment the index of the device we are looking at as well as the number
		# of our current command.
		num += 1
		index += 1
	# Finally, create a dynamic port to port 9050 that can be utilized with proxychains
	cmd_list.append([num,"ssh -D 9050 -p " + curr_rport + " " + devices[-1].username + "@localhost"])
	cmd_list.append([num,devices[-1].password])

	return cmd_list

def run_commands(cmd_list):
	"""
	Args: list of commands to run
	Return: a list of processes running that create a tunnel
	"""
	try:
		### Iterate through each cmd in our cmd list, creating a new process for each
		# 	number of the command.
		procs = []
		prev_num = 0
		for cmd_pair in cmd_list:
			num,cmd=cmd_pair
			if debug: print("Running command: ", cmd)
			# If it's a new number, spawn this as a new process.
			if num != prev_num:
				proc = pexpect.spawn(cmd)
				procs.append(proc)
				if debug: print("Command exception.")
				code = proc.expect(["word:","login:","failed.","\?"], timeout = 1)
				if debug: print("Code: ", code)
				### If we hit code 2, we have an error related to ssh keys.
				# 	In response, we flush all possible problematic keys that
				# 	might have been previously generated.
				if code == 2:
					os.system('ssh-keygen -f "/home/student/.ssh/known_hosts" -R "localhost" >/dev/null 2>&1')
					bad_port = cmd.split(" ")[4]
					os.system('ssh-keygen -f "/home/student/.ssh/known_hosts" -R [localhost]:' + bad_port + ' >/dev/null 2>&1')
					second_bad_port = cmd.split(" ")[2]
					os.system('ssh-keygen -f "/home/student/.ssh/known_hosts" -R [localhost]:' + second_bad_port + ' >/dev/null 2>&1')
					third_bad_port = cmd.split(" ")[-1]
					os.system('ssh-keygen -f "/home/student/.ssh/known_hosts" -R [localhost]:' + third_bad_port + ' >/dev/null 2>&1')
					proc = pexpect.spawn(cmd)
					procs.append(proc)
					proc.expect("\?", timeout = 1)
					proc.sendline("yes")
					proc.expect(["word:","login:"], timeout = 1)
				elif code == 3:
					proc.sendline("yes")
					proc.expect(["word:","login:"], timeout = 1)
			else:
				### If we're on the same process, we probably need to send
				#	Usernames and/or passwords.
				proc = procs[-1]
				proc.sendline(cmd)
				try:
					proc.expect('\$', timeout = 1)
				except:
					try:
						proc.expect("\?", timeout = 1)
						proc.sendline("yes")
						proc.expect(["word:","login:"], timeout = 1)
					except:
						proc.expect(["word:","login:"], timeout = 1)
			prev_num = num
	except:
		# If this attempt fails, kill our existing processes and exit.
		kill_processes(procs)
		return []
	return procs

### The following function simulates pressing control-c and inputting 'exit' until
#	each process is dead.
def kill_processes(procs):
	"""
	Args: a list of running processes
	Returns: none, just kills all of the processes
	"""
	if debug: print("Killing {0} processes...".format(len(procs)))
	if len(procs)>=1:
		for proc in procs:
			while proc.isalive():
				try:
					proc.sendcontrol('c')
					proc.expect(pexpect.EOF, timeout = 0.5)
				except:
					pass
				try:
					proc.sendline('exit')
					proc.expect(pexpect.EOF, timeout = 0.5)
				except:
					pass
	return


def build_tunnel():
	"""
	Args: none, will be supplied by user input.
	Returns: none, a dynamic port will be linked to the last machine.
	"""
	devices, rport = request_devices()
	cmds = generate_commands(devices, rport)
	print('-----------------------')
	print('\n')
	for cmd in cmds:
		print("{0}: {1}".format(cmd[0],cmd[1]))
	print("\nPlease wait while I establish your connection...")
	proc_list = run_commands(cmds)
	print("Your connection is good to go!")
	print("\nEnter 'kill' when you're ready to kill these processes! Input:")
	user_inp = input()
	while user_inp.lower() != 'kill':
		if user_inp.lower() == 'restart':
			print("Restarting your processes, please wait...")
			kill_processes(proc_list)
			proc_list = run_commands(cmds)
			print("Restart complete! Enter 'kill' when you're done:")
		user_inp = input()
	kill_processes(proc_list)
	print("All your spawned processes are killed!")

if __name__ == "__main__":
	debug = False
	build_tunnel()
