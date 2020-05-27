#!/usr/bin/python

import sys
import os
import re
import hashlib
import enchant

DICT = enchant.Dict('en_US')
OWN_DICT = frozenset(('addr', 'aes', 'arg', 'cmd', 'ciphertext', 'del', 'desc', 'dev', 'dst', 'eax', 'ebx', 'ecx', 'edx', 'endianness', 'gettime', 'grep', 'hmac', 'init', 'len', 'linux', 'malloc', 'mem', 'msg', 'nb', 'pci', 'pe', 'pid', 'plaintext', 'prev', 'proc', 'ptr', 'ptrace', 'rb', 'realloc', 'ret', 'shl', 'shr', 'sizeof', 'snprintf', 'src', 'str', 'struct', 'sudo', 'tmp', 'tsearch', 'wunused', 'xor', 'xtea'))

EXCLUDE = ('.git')

RE_TOKENIZE_WORD = re.compile(r'(?<!%)[a-zA-Z][a-z]*')

CONFIG_TAB_SIZE = 4
CONFIG_VERBOSE = False
CONFIG_MAX_REPORT = 10

CHECK_ALIGN_MUL_MACRO 	= 1
CHECK_DOUBLE_SPACE 		= 2
CHECK_EMPTY_FILE 		= 3
CHECK_EMPTYL_BEG 		= 4
CHECK_EMPTYL_END 		= 5
CHECK_EXPLICIT_NZCOND 	= 6
CHECK_EXPLICIT_ZCOND 	= 7
CHECK_INDENT_SPACE 		= 8
CHECK_MALLOC_CAST 		= 9
CHECK_NEW_LINE_EOF 		= 10
CHECK_MISSING_VOID_PROT = 11
CHECK_RECURSIVE_INCLUDE = 12
CHECK_SPACE_BRACE 		= 13
CHECK_SPACE_CL_BRACKET 	= 14
CHECK_SPACE_COND 		= 15
CHECK_SPACE_EOL 		= 16
CHECK_SEVERAL_SEMICOL 	= 17
CHECK_SPELLING 			= 18
CHECK_WINDOWS_CARRIAGE 	= 19

HASH_SET = set()

def hash_file(file_name):
	sha256 = hashlib.sha256()

	with open(file_name, 'rb') as f:
		while True:
			data = f.read(65536)
			sha256.update(data)
			if len(data) != 65536:
				break

	return sha256.digest()

def is_elf_file(file_name):
	with open(file_name, 'rb') as f:
		elf_hdr = f.read(16)
	if len(elf_hdr) != 16:
		return False
	if not elf_hdr[ : 4] == '\x7fELF': # magic
		return False
	if elf_hdr[4] not in ('\x00', '\x01', '\x02'): # class
		return False
	if elf_hdr[5] not in ('\x00', '\x01', '\x02'): # encoding
		return False
	return elf_hdr[9 : ] == '\x00\x00\x00\x00\x00\x00\x00'

def report(check_id, file_name, line, auto, arg=None):
	string = "??"

	if check_id == CHECK_ALIGN_MUL_MACRO:
		string = 'alignment in multi-line macro'
	elif check_id == CHECK_DOUBLE_SPACE:
		string = 'double space'
	elif check_id == CHECK_EMPTY_FILE:
		string = 'empty file'
	elif check_id == CHECK_EMPTYL_BEG:
		string = 'empty line at the beginning of file'
	elif check_id == CHECK_EMPTYL_END:
		string = 'empty line at the end of file'
	elif check_id == CHECK_EXPLICIT_NZCOND:
		string = 'explicit non-zero condition'
	elif check_id == CHECK_EXPLICIT_ZCOND:
		string = 'explicit zero condition'
	elif check_id == CHECK_INDENT_SPACE:
		string = 'indented with space'
	elif check_id == CHECK_MALLOC_CAST:
		string = 'explicit cast result of malloc/realloc'
	elif check_id == CHECK_MISSING_VOID_PROT:
		string = 'missing void in prototype'
	elif check_id == CHECK_NEW_LINE_EOF:
		string = 'no new line at EOF'
	elif check_id == CHECK_RECURSIVE_INCLUDE:
		string = 'non standard / missing protection to prevent recursive include'
	elif check_id == CHECK_SPACE_BRACE:
		string = 'no space before / after brace'
	elif check_id == CHECK_SPACE_CL_BRACKET:
		string = 'unintended space before closing bracket'
	elif check_id == CHECK_SPACE_COND:
		string = 'no space before condition'
	elif check_id == CHECK_SPACE_EOL:
		string = 'space(s) / tab(s) at EOL'
	elif check_id == CHECK_SEVERAL_SEMICOL:
		string = 'several semi-column'
	elif check_id == CHECK_SPELLING:
		string = 'spell check'
	elif check_id == CHECK_WINDOWS_CARRIAGE:
		string = 'Windows carriage return'

	try:
		check_id_loc = report.check_id
	except AttributeError:
		report.check_id = check_id
	try:
		file_name_loc = report.file_name
	except AttributeError:
		report.file_name = file_name
	try:
		counter_loc = report.counter
	except AttributeError:
		report.counter = 0

	if report.check_id != check_id or report.file_name != file_name:
		report.file_name = file_name
		report.check_id = check_id
		report.counter = 0

	if CONFIG_VERBOSE or report.counter < CONFIG_MAX_REPORT:
		sys.stdout.write(file_name + ':' + str(line) + ' - ' + string)
		if arg != None:
			sys.stdout.write(' ' + arg)
		if not auto:
			sys.stdout.write(' [no auto-correct]\n')
		else:
			sys.stdout.write('\n')
	elif report.counter == CONFIG_MAX_REPORT:
		sys.stdout.write('\x1b[33m[-]\x1b[0m stop reporting: \'' + string + '\' for file ' + file_name + '\n')
	report.counter += 1

def generic_spelling(strings, file_name, line, file_typo):
	for string in strings:
		words = RE_TOKENIZE_WORD.findall(string)
		for word in words:
			lword = word.lower()
			if len(word) < 32 and not DICT.check(word) and lword not in OWN_DICT and lword not in file_typo:
				report(CHECK_SPELLING, file_name, line, False, '\x1b[31m' + word + '\x1b[0m in ' + string)
				file_typo.add(lword)

def sscan_text(lines, file_name):
	result = 0

	# Check empty file
	if not lines:
		report(CHECK_EMPTY_FILE, file_name, 0, False)
	else:
		# Check Windows newline
		for i, line in enumerate(lines):
			if line.find('\r') != -1:
				report(CHECK_WINDOWS_CARRIAGE, file_name, i + 1, True)
				lines[i] = line.replace('\r', '')
				result = 1

		# Check empty lines
		if lines[-1][-1] != '\n':
			report(CHECK_NEW_LINE_EOF, file_name, len(lines), True)
			lines[-1] = lines[-1] + '\n'
			result = 1
		elif lines[-1] == '\n':
			report(CHECK_EMPTYL_END, file_name, len(lines), True)
			while lines and lines[-1] == '\n':
				lines = lines[:-1]
			result = 1
		if not lines:
			report(CHECK_EMPTY_FILE, file_name, 0, False)
		else:
			if lines[0] == '\n':
				report(CHECK_EMPTYL_BEG, file_name, 1, True)
				while lines[0] == '\n':
					lines = lines[1:]
				result = 1

			# Space or tab at end of line
			regex = re.compile(r'[ \t]+$')
			for i, line in enumerate(lines):
				if regex.findall(line):
					report(CHECK_SPACE_EOL, file_name, i + 1, True)
					lines[i] = regex.sub('', line)
					result = 1

	return result, lines

def sscan_ccode(lines, file_name):
	result = 0

	# Double space
	regex = re.compile(r'( {2}|\t )')
	for i, line in enumerate(lines):
		if regex.findall(line):
			report(CHECK_INDENT_SPACE, file_name, i + 1, False)

	# Space before condition
	regex = re.compile(r'(^|[\t }])(if|for|while|switch)\(')
	for i, line in enumerate(lines):
		if regex.findall(line):
			report(CHECK_SPACE_COND, file_name, i + 1, True)
			lines[i] = regex.sub(r'\1\2 (', line)
			result = 1

	# Explicit non-zero condition
	regex = re.compile(r'(!= *0[ )&|]|[ (&|]0 *!=)')
	for i, line in enumerate(lines):
		if regex.findall(line):
			report(CHECK_EXPLICIT_NZCOND, file_name, i + 1, False)

	# Explicit zero condition
	regex = re.compile(r'(== *0[ )&|]|[ (&|]0 *==)')
	for i, line in enumerate(lines):
		if regex.findall(line):
			report(CHECK_EXPLICIT_ZCOND, file_name, i + 1, False)

	# Remove unnecessary cast
	regex = re.compile(r'\([^()]+\*\)(malloc|realloc)\(')
	for i, line in enumerate(lines):
		if regex.findall(line):
			report(CHECK_MALLOC_CAST, file_name, i + 1, True)
			lines[i] = regex.sub(r'\1(', line)
			result = 1

	# Spell check strings
	regex1 = re.compile(r'(?<!include )"[^"]*"')
	regex2 = re.compile(r'%[0-9]*(c|d|p|s|u|x|lld|llu|llx)')
	file_typo = set()
	for i, line in enumerate(lines):
		strings = regex1.findall(line)
		strings = [regex2.sub('', string) for string in strings]
		generic_spelling(strings, file_name, i + 1, file_typo)

	# Non-void prototype
	regex = re.compile(r'([a-zA-Z0-9_]+)[ ]*\(\)[ ]*\{')
	for i, line in enumerate(lines):
		if regex.findall(line):
			report(CHECK_MISSING_VOID_PROT, file_name, i + 1, True)
			lines[i] = regex.sub(r'\1(void){', line)
			result = 1

	# Space before brace for struct/enum/union definition
	regex = re.compile(r'((struct|enum|union) [a-zA-Z0-9_]+){')
	for i, line in enumerate(lines):
		if regex.findall(line):
			report(CHECK_SPACE_BRACE, file_name, i + 1, True)
			lines[i] = regex.sub(r'\1 {', line)
			result = 1

	# Space before brace for else/do statement
	regex = re.compile(r'((else|do)){')
	for i, line in enumerate(lines):
		if regex.findall(line):
			report(CHECK_SPACE_BRACE, file_name, i + 1, True)
			lines[i] = regex.sub(r'\1 {', line)
			result = 1

	# Space after closing brace for do ... while statement
	regex = re.compile(r'}while')
	for i, line in enumerate(lines):
		if regex.findall(line):
			report(CHECK_SPACE_BRACE, file_name, i + 1, True)
			lines[i] = regex.sub(r'} while', line)
			result = 1

	# More than one semi column
	regex = re.compile(r';;+')
	for i, line in enumerate(lines):
		if regex.findall(line):
			report(CHECK_SEVERAL_SEMICOL, file_name, i + 1, False)
			# no auto correct because it is a rare mistake and correction will mess up with the for (;;){ syntax

	# Multi-line macro
	prev_size = 0
	for i, line in enumerate(lines):
		if line[-2:] == '\\\n':
			size = 0
			for c in line[:-2]:
				if c == '\t':
					size += CONFIG_TAB_SIZE - (size % CONFIG_TAB_SIZE)
				else:
					size += 1
			if prev_size:
				if size > prev_size:
					report(CHECK_ALIGN_MUL_MACRO, file_name, i + 1, False)
				if size < prev_size:
					while size < prev_size:
						lines[i] = lines[i][:-2] + '\t\\\n'
						size += CONFIG_TAB_SIZE - (size % CONFIG_TAB_SIZE)
						result = 1
					report(CHECK_ALIGN_MUL_MACRO, file_name, i + 1, True)
			elif size % CONFIG_TAB_SIZE:
				lines[i] = lines[i][:-2] + '\t\\\n'
				prev_size = size + CONFIG_TAB_SIZE - (size % CONFIG_TAB_SIZE)
				report(CHECK_ALIGN_MUL_MACRO, file_name, i + 1, True)
				result = 1
			else:
				prev_size = size
		else:
			prev_size = 0

	return result, lines

def sscan_cheader(lines, file_name):
	# Recursive include protection
	if len(lines) < 3:
		report(CHECK_RECURSIVE_INCLUDE, file_name, 0, False)
	else:
		if lines[0] != '#ifndef ' + os.path.basename(file_name)[:-2].upper() + '_H\n':
			report(CHECK_RECURSIVE_INCLUDE, file_name, 1, False)
		elif lines[1] != '#define ' + os.path.basename(file_name)[:-2].upper() + '_H\n':
			report(CHECK_RECURSIVE_INCLUDE, file_name, 2, False)
		elif lines[-1] != '#endif\n':
			report(CHECK_RECURSIVE_INCLUDE, file_name, len(lines), False)

	return 0, lines

def sscan_pcode(lines, file_name):
	# Double space in the middle of a line
	for i, line in enumerate(lines):
		for j, b in enumerate(line):
			if b != ' ' or b != '\t':
				if line[j:].find('  ') != -1:
					report(CHECK_DOUBLE_SPACE, file_name, i + 1, False)
				break

	# Space before closing bracket
	for i, line in enumerate(lines):
		for j, b in enumerate(line):
			if b != ' ' or b != '\t':
				if line.find(' )') != -1:
					report(CHECK_SPACE_CL_BRACKET, file_name, i + 1, False)
				break

	return 0, lines

def dispatcher(rootname, filename):
	sscan_list = []

	basename = os.path.basename(filename)
	fullname = os.path.join(rootname, filename)

	# Rename file
	newname = None
	if basename.endswith('.yar'):
		newname = fullname + 'a'
	elif filename.find(' ') != -1:
		newname = os.path.join(rootname, filename.replace(' ', '_'))

	if newname:
		os.rename(fullname, newname)
		sys.stdout.write('\x1b[32m[+]\x1b[0m file ' + fullname + ' move to ' + newname + '\n')
		fullname = newname
		basename = os.path.basename(newname)

	sha256 = hash_file(fullname)
	if sha256 in HASH_SET:
		sys.stdout.write('\x1b[33m[-]\x1b[0m file ' + fullname + ' is a duplicate\n')
	else:
		HASH_SET.add(sha256)

	if basename.endswith('.a'):
		return
	elif basename.endswith('.asm'):
		sscan_list = [sscan_text]
	elif basename.endswith('.bin'):
		return
	elif basename.endswith('.c'):
		sscan_list = [sscan_text, sscan_ccode]
	elif basename.endswith('.cpp'):
		sscan_list = [sscan_text, sscan_ccode]
	elif basename.endswith('.dll'):
		return
	elif basename.endswith('.exe'):
		return
	elif basename == '.gitignore':
		sscan_list = [sscan_text]
	elif basename.endswith('.h'):
		sscan_list = [sscan_text, sscan_ccode, sscan_cheader]
	elif basename.endswith('.html'):
		sscan_list = [sscan_text]
	elif basename.endswith('.js'):
		sscan_list = [sscan_text]
	elif basename.endswith('.ko'):
		return
	elif basename.endswith('.log'):
		return
	elif basename.endswith('.md'):
		sscan_list = []
	elif basename.endswith('.o'):
		return
	elif basename.endswith('.obj'):
		return
	elif basename.endswith('.py'):
		sscan_list = [sscan_text, sscan_pcode]
	elif basename.endswith('.pyc'):
		return
	elif basename.endswith('.rb'):
		sscan_list = [sscan_text]
	elif basename.endswith('.sh'):
		sscan_list = [sscan_text]
	elif basename.endswith('.so'):
		return
	elif basename.endswith('.symvers'):
		return
	elif basename.endswith('.sys'):
		return
	elif basename.endswith('.txt'):
		sscan_list = [sscan_text]
	elif basename.endswith('.yara'):
		sscan_list = [sscan_text]
	elif basename.endswith('.xml'):
		sscan_list = [sscan_text]
	elif basename.endswith('.zip'):
		return
	elif basename == 'Makefile':
		sscan_list = [sscan_text]
	else:
		if not is_elf_file(fullname):
			sys.stdout.write('\x1b[33m[-]\x1b[0m file ' + fullname + ' has no known type -> skip\n')
		return

	file = open(fullname, 'r')
	lines = file.readlines()
	file.close()

	result = 0

	for sscan in sscan_list:
		local_result, lines = sscan(lines, fullname)
		result |= local_result

	if result:
		file = open(fullname, 'w')
		for line in lines:
			file.write(line)
		file.close()
		sys.stdout.write('\x1b[32m[+]\x1b[0m fixed problem(s) in ' + fullname + '\n')

if __name__ == '__main__':
	if len(sys.argv) < 2:
		sys.stderr.write('\x1b[31m[!]\x1b[0m Usage: ' + sys.argv[0] + ' [-v] path\n')
		sys.exit(1)

	path_args = []
	for arg in sys.argv[1:]:
		if arg == '-v':
			CONFIG_VERBOSE = True
		else:
			path_args.append(arg)

	for arg in path_args:
		if os.path.isdir(arg):
			for root, subdirs, files in os.walk(arg, topdown=True):
				subdirs[:] = [subdir for subdir in subdirs if subdir not in EXCLUDE]
				for file in files:
					dispatcher(root, file)
		elif arg not in EXCLUDE:
			dispatcher('', arg)
