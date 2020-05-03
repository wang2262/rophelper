#!/usr/bin/env python3

import pexpect
import csv

syscalls = {}
registers = ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9', 'rax']
registers_16 = ['edi', 'esi', 'edx', 'r10d', 'r8d', 'r9d', 'eax']
ops = ['pop', 'dec', 'inc', 'lea', 'xchg', 'add', 'sub', 'imul', 'idiv', 'mov']
with open("syscall_table", mode='r') as csvfile:
	csvreader = csv.DictReader(csvfile)
	for row in csvreader:
		args = []
		for i in range(6):
			if row['arg' + str(i)]:
				args.append(row['arg' + str(i)])
			else:
				break
		syscalls.update({row['syscall']: [int(row['rax'], 10), args]})

def printGadgets(process, filepath):
	process.expect("> ", timeout=None)
	s = process.before.decode('utf-8')
	start = s.find('File: ' + filepath + '\r\n') + len(filepath) + 8
	end = s.find('\r\n\r\n(')
	if start == len(filepath) + 7:
		return 0
	print(s[start:end])
	return 1

def searchGadgets(process, filepath, op, reg, value):
	if op == 'syscall':
		command = 'search syscall'
	else:
		command = 'search ' + op + " " + reg
	if op == 'xor':
		command = command + ', ' + reg
	elif op == 'mov' and value:
		command = command + ', ' + value
	print("[info]: " + command)
	process.sendline(command)
	if printGadgets(process, filepath) == 0:
		if reg in registers:
			reg = registers_16[registers.index(reg)]
			searchGadgets(process, filepath, op, reg, value)


def listSyscalls():
	for key, value in syscalls.items():
		print(key + "(", end="")
		print(*value[1], sep = ", ", end="")
		print(")")

def main():
	process = pexpect.spawn("ropper --nocolor")
	process.expect(" ", timeout=None)
	filepath = input('File path:\n> ')
	command = 'file ' + filepath
	process.sendline(command)
	process.expect("> ", timeout=None)
	
	if (b"x86_64" not in process.before):
		print('supports x86_64 binaries\n')
		return
	while(1):
		syscall = input("\nsyscall:\n> ")
		while (syscall == 'list'):
			listSyscalls()
			syscall = input("\nsyscall:\n> ")
		if (syscall == 'quit'):
			process.close()
			return
		if (syscall in syscalls.keys()):
			rax = hex(syscalls[syscall][0])
			argc = len(syscalls[syscall][1])
			print('{} args:'.format(argc))
			for i in range(argc):
				while(1):
					arg = input("> ")
					if (arg == 'quit'):
						process.close()
						return
					if (arg.startswith('0x')):
						hexvalue = arg
						break
					elif arg.isdigit():
						hexvalue = hex(int(arg, 10))
						break
					else:
						print("Invalid command")
				print(registers[i] + "=" + hexvalue)
				for op in ops:
					searchGadgets(process, filepath, op, registers[i], '')
				searchGadgets(process, filepath, "mov", registers[i], hexvalue)
				if (arg == '0'):
					searchGadgets(process, filepath, "xor", registers[i], '')
			print("-----------------------------------------------------------------")
			print("rax=" + rax)
			for op in ops:
				searchGadgets(process, filepath, op, 'rax', '')
			searchGadgets(process, filepath, 'mov', 'rax', rax)
			searchGadgets(process, filepath, 'syscall', '', '')
		else:
			print("Invalid command")
main()