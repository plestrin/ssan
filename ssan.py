#!/usr/bin/python

import sys
import os
import re
import enchant

DICT = enchant.Dict('en_US')
OWN_DICT = frozenset(('aes', 'arg', 'cmd', 'ciphertext', 'del', 'desc', 'dst', 'eax', 'ebx', 'ecx', 'edx', 'gettime', 'hmac', 'init', 'malloc', 'mem', 'msg', 'plaintext', 'prev', 'ptr', 'realloc', 'shl', 'shr', 'snprintf', 'src', 'str', 'tsearch', 'wunused', 'xor', 'xtea'))

EXCLUDE = ('.git')

RE_TOKENIZE_WORD = re.compile(r'(?<!%)[a-zA-Z][a-z]*')

TAB_SIZE = 4 

def check_spelling(string, file_name, line):
	global DICT
	global OWN_DICT
	global RE_TOKENIZE_WORD

	words = RE_TOKENIZE_WORD.findall(string)
	for word in words:
		if len(word) < 32 and not DICT.check(word) and word.lower() not in OWN_DICT:
			sys.stdout.write(file_name + ':' + str(line) + ' - spell check: \x1b[31m' + word + '\x1b[0m in ' + string + ' (no auto correct!)\n')
	

def sscan_text(lines, file_name):
	result = 0

	# Check empty file
	if not len(lines):
		sys.stdout.write(file_name + ' - empty file\n')

	# Check Windows newline
	for i, line in enumerate(lines):
		if line.find('\r') != -1:
			sys.stdout.write(file_name + ':' + str(i + 1) + ' - Windows end of file\n')
			lines[i] = line.replace('\r', '')
			result = 1

	# Check empty lines
	if lines[-1][-1] != '\n':
		sys.stdout.write(file_name + ' - no empty line at the end of file\n')
		lines[-1] = lines[-1] + '\n'
		result = 1
	elif lines[-1] == '\n':
		sys.stdout.write(file_name + ':' + str(len(lines)) + ' - too many empty lines at the end of file\n')
		while lines[-1] == '\n' and len(lines):
			lines = lines[:-1]
		result = 1
	if lines[0] == '\n':
		sys.stdout.write(file_name + ':0 - too many empty lines at the beginning of file\n')
		while lines[0] == '\n':
			lines = lines[1:]
		result = 1

	# Space or tab at end of line
	regex = re.compile(r'[ \t]+$')
	for i, line in enumerate(lines):
		if len(regex.findall(line)):
			sys.stdout.write(file_name + ':' + str(i + 1) + ' - space(s) or tab(s) at end of line\n')
			lines[i] = regex.sub('', line)
			result = 1

	return result, lines

def sscan_ccode(lines, file_name):
	global TAB_SIZE

	result = 0

	# Double space
	regex = re.compile(r'( {2}|\t )')
	j = 0
	for i, line in enumerate(lines):
		if len(regex.findall(line)) > 0:
			sys.stdout.write(file_name + ':' + str(i + 1) + ' - this line seems to be indented with space\n')
			j += 1
		if j >= 10:
			sys.stdout.write('\x1b[33m[-]\x1b[0m too many spaces, in' + file_name + ': stop reporting\n')
			break

	# Space before condition
	regex = re.compile(r'(^|[\t }])(if|for|while|switch)\(')
	for i, line in enumerate(lines):
		if len(regex.findall(line)) > 0:
			sys.stdout.write(file_name + ':' + str(i + 1) + ' - no space before condition\n')
			lines[i] = regex.sub(r'\1\2 (', line)
			result = 1

	# Explicit non-zero condition
	regex = re.compile(r'(!= *0[ )&|]|[ (&|]0 *!=)')
	for i, line in enumerate(lines):
		if len(regex.findall(line)) > 0:
			sys.stdout.write(file_name + ':' + str(i + 1) + ' - explicit non-zero condition (no auto correct!)\n')

	# Explicit zero condition
	regex = re.compile(r'(== *0[ )&|]|[ (&|]0 *==)')
	for i, line in enumerate(lines):
		if len(regex.findall(line)) > 0:
			sys.stdout.write(file_name + ':' + str(i + 1) + ' - explicit zero condition (no auto correct!)\n')

	# Remove unnecessary cast
	regex = re.compile(r'\([^()]+\*\)(malloc|realloc)\(')
	for i, line in enumerate(lines):
		if len(regex.findall(line)) > 0:
			sys.stdout.write(file_name + ':' + str(i + 1) + ' - explicit cast result of malloc/realloc\n')
			lines[i] = regex.sub(r'\1(', line)
			result = 1

	# Spell check strings
	regex1 = re.compile(r'(?<!include )"[^"]*"')
	regex2 = re.compile(r'%[0-9]*(c|d|p|s|u|x|lld|llu|llx)')
	for i, line in enumerate(lines):
		strings = regex1.findall(line)
		for string in strings:
			check_spelling(regex2.sub('', string), file_name, i + 1)

	# Non-void prototype
	regex = re.compile(r'([a-zA-Z0-9_]+)[ ]*\(\)\{')
	for i, line in enumerate(lines):
		if len(regex.findall(line)) > 0:
			sys.stdout.write(file_name + ':' + str(i + 1) + ' - non-void function prototype\n')
			lines[i] = regex.sub(r'\1(void){', line)
			result = 1

	# Multi-line macro
	prev_size = 0
	for i, line in enumerate(lines):
		if line[-2:] == '\\\n':
			size = 0
			for c in line[:-2]:
				if c == '\t':
					size += TAB_SIZE - (size % TAB_SIZE)
				else:
					size += 1
			if prev_size:
				if size > prev_size:
					sys.stdout.write(file_name + ':' + str(i + 1) + ' - align multi-line macro, line too long (no auto correct!)\n')
				if size < prev_size:
					while size < prev_size:
						lines[i] = lines[i][:-2] + '\t\\\n'
						size +=  TAB_SIZE - (size % TAB_SIZE)
						result = 1
					sys.stdout.write(file_name + ':' + str(i + 1) + ' - align multi-line macro\n')
			elif size % TAB_SIZE:
				lines[i] = lines[i][:-2] + '\t\\\n'
				prev_size = size + TAB_SIZE - (size % TAB_SIZE)
				sys.stdout.write(file_name + ':' + str(i + 1) + ' - align multi-line macro\n')
				result = 1
			else:
				prev_size = size
		else:
			prev_size = 0




	return result, lines

def sscan_cheader(lines, file_name):
	# Recursive include protection
	if len(lines) < 3:
		sys.stdout.write(file_name + ':1 - non standard / missing protection to prevent recursive include (no auto correct!)\n')
	else:
		if lines[0] != '#ifndef ' + os.path.basename(file_name)[:-2].upper() + '_H\n':
			sys.stdout.write(file_name + ':1 - non standard / missing protection to prevent recursive include (no auto correct!)\n')
		elif lines[1] != '#define ' + os.path.basename(file_name)[:-2].upper() + '_H\n':
			sys.stdout.write(file_name + ':2 - non standard / missing protection to prevent recursive include (no auto correct!)\n')
		elif lines[-1] != '#endif\n':
			sys.stdout.write(file_name + ':' + str(len(lines)) + ' - non standard / missing protection to prevent recursive include (no auto correct!)\n')

	return 0, lines

def dispatcher(root_name, file_name):
	sscan_list = []

	if file_name.endswith('.asm'):
		sscan_list = [sscan_text]
	elif file_name.endswith('.c'):
		sscan_list = [sscan_text, sscan_ccode]
	elif file_name.endswith('.cpp'):
		sscan_list = [sscan_text, sscan_ccode]
	elif file_name == '.gitignore':
		sscan_list = [sscan_text]
	elif file_name.endswith('.h'):
		sscan_list = [sscan_text, sscan_ccode, sscan_cheader]
	elif file_name.endswith('.html'):
		sscan_list = [sscan_text]
	elif file_name.endswith('.js'):
		sscan_list = [sscan_text]
	elif file_name.endswith('.md'):
		sscan_list = [sscan_text]
	elif file_name.endswith('.o'):
		return
	elif file_name.endswith('.py'):
		sscan_list = [sscan_text]
	elif file_name.endswith('.pyc'):
		return
	elif file_name.endswith('.sh'):
		sscan_list = [sscan_text]
	elif file_name.endswith('.txt'):
		sscan_list = [sscan_text]
	elif file_name.endswith('.yara'):
		sscan_list = [sscan_text]
	elif file_name.endswith('.xml'):
		sscan_list = [sscan_text]
	elif file_name == 'Makefile':
		sscan_list = [sscan_text]
	else:
		sys.stdout.write('\x1b[33m[-]\x1b[0m file ' + os.path.join(root_name, file_name) + ' has no known type -> skip\n')
		return

	file = open(os.path.join(root_name, file_name), 'r')
	lines = file.readlines()
	file.close()

	result = 0

	for sscan in sscan_list:
		local_result, lines = sscan(lines, os.path.join(root_name, file_name))
		result |= local_result

	if result:
		sys.stdout.write('\x1b[32m[+]\x1b[0m fixed problem(s) in ' + os.path.join(root_name, file_name) + '\n')
		file = open(os.path.join(root_name, file_name), 'w')
		for line in lines:
			file.write(line)
		file.close()

if __name__ == '__main__':
	if len(sys.argv) < 2:
		sys.stderr.write('\x1b[31m[!]\x1b[0m no file or directory specified\n')
		sys.exit(1)

	for arg in sys.argv[1:]:
		if os.path.isdir(arg):
			for root, subdirs, files in os.walk(arg, topdown=True):
				subdirs[:] = [subdir for subdir in subdirs if subdir not in EXCLUDE]
				for file in files:
					dispatcher(root, file)
		else:
			dispatcher('', arg)
