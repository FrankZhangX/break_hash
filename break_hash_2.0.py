import hashlib
import os
import itertools

#判断并设置哈希算法
def judge(length):
	method = ''
	if length == 32:
		method = 'md5'
		ha = hashlib.md5()
	elif length == 40:
		method = 'sha1'
		ha = hashlib.sha1()
	elif length == 56:
		method = 'sha224'
		ha = hashlib.sha224()
	elif length == 64:
		method = 'sha256'
		ha = hashlib.sha256()
	elif length == 96:
		method = 'sha384'
		ha = hashlib.sha384()
	elif length == 128:
		method = 'sha512'
		ha = hashlib.sha512()

	print('\n该哈希值为', method, '算法计算所得\n')
	'''
	名称 	描述							长度
	md5(…) 	利用md5算法加密				32
	sha1(…) 	利用sha1算法加密         40
	sha224(…) 	利用sha224算法加密		56
	sha256(…) 	利用sha256算法加密		64
	sha384(…) 	利用sha384算法加密		96
	sha512(…) 	利用sha512算法加密		128
	'''
	return ha

#设置明文长度
def set_length():
	min = max = 0
	print('\n请分别设置明文最小最大长度，可设置两者大小相同\n')
	print('Please set the min and max length.They could be the same.\n')
	while 1:
		while 1:
			try:
				min = int(input('\n请输入明文的最短长度：\nPlease input the min length:'))
				break
			except:
				print('\n输入内容不符\n')
		while 1:
			try:
				max = int(input('\n请输入明文的最长长度：\nPlease input the max length:'))
				break
			except:
				print('\n输入内容不符\n')
		if min > max:
			print('\n最短长度大于最长长度，重新输入\nTry again\n')
			continue
		else:
			return min, max

#进行哈希计算
def calculate(plain, method):
	print(plain)
	ha_ = method.copy()
	ha_.update(plain.encode("utf-8"))	#Unicode-objects must be encoded before hashing
	print(ha_.hexdigest())
	return ha_.hexdigest()

#开始进行爆破
def start_break(method, hashed, min = 0, max = 0, chars = None, dic = None):
	flag = 0	#标志是否爆破成功
	if dic == None:
		for length in range(min, max+1):
			for one in itertools.product(chars, repeat = length):
				one = ''.join(one)
				hashed_ = calculate(one, method)

				if hashed_ == hashed:
					print('\nFOUND:', one, '\n')
					flag = 1
					break

	elif dic != None:
		for single in dic:
			cut = single[:-1]
			hashed_ = calculate(cut, method)

			if hashed_ == hashed:
				print('\nFOUND:', cut, '\n')
				with open('result.txt', 'a') as f:
					f.write(cut+'\n')
				flag = 1
				break

	if flag == 0:
		print('\n无结果\n404:Not Found\n')

#纯字符爆破
def chars_break(method, hashed):
	min, max = set_length()
	while 1:
		try:
			print('\n1.数字	2.大写字母	3.小写字母	4.其他字符\n')
			options = input('\n请选择纯字符：')
			break
		except:
			print('\n输入不在选项内\n')

	options = cancel_repeat(options)
	options = list(options)

	for option in options:
		#判断纯字符
		if option == '1':
			chars = '0123456789'
		elif option == '2':
			chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
		elif option == '3':
			chars = 'abcdefghijklmnopqrstuvwxyz'
		elif option == '4':
			chars = '!@#$%^&*()_+-=[]\\{}|;\':",./<>? '


		#开始进行爆破
		start_break(method, hashed, min, max, chars)


#字典爆破
def dic_break(method, hashed):
	#导入字典
	while 1:
		try:
			dic = input('\n请输入你想导入的字典：\nPlease input the name of your directory:')
			with open(dic,'r') as f:
				break_dic = f.readlines()
			break
		except:
			print('No such directory.Try again!')

	#开始字典爆破
	start_break(method, hashed, dic = break_dic)

#提取包含字符，去重
def cancel_repeat(origin):
    origin_list = list(origin)
    char_ = []
    for i in origin_list:
        if i not in char_:
            char_.append(i)
    char = ''.join(char_)
    return char

#自定义字符爆破
def self_define(method, hashed):
	origin = input('请输入需要包含的明文字符：')
	chars = cancel_repeat(origin)
	min, max = set_length()
	
	#开始进行字符串爆破
	start_break(method, hashed, min, max, chars)


if __name__ == '__main__':
	
	print('\n本程序可通过导入字典文件可对不同哈希值进行爆破，字典可使用字典生成工具生成')
	print('可针对md5 sha1 sha224 sha256 sha384 sha512六种常见类型进行爆破')
	print('可自动对哈希类型进行判断，爆破结果将写入 result.txt 文件中\n')

	flag = 1
	#输入哈希值
	while flag:
		try:
			hashed = input('\n请输入将要爆破的哈希值：\nPlease input the hash code:')
			hashed = hashed.lower()
			length = len(hashed)
			if length not in [32,40,56,64,96,128]:
				print('\n无效哈希值\nThe hash value is unavailible.\n')
				continue
			flag = 0
		except Exception as e:
			print(e)

	#判断哈希算法
	method = judge(length)

	#选择爆破方式
	while 1:
		try:
			print('1.纯字符	2.自定义字符	3.字典')
			option = int(input('\n请选择爆破方式：\nPlease select the option:'))
			if option not in [1, 2, 3]:
				print('\n输入不在选项内\n')
				continue
			break
		except:
			print('\n输入不在选项内\n')

	#纯字符爆破
	if option == 1:
		print('\n选择的爆破方式为 纯数字爆破\n')
		chars_break(method, hashed)
		
	#自定义字符
	elif option == 2:
		print('\n选择的爆破方式为 自定义字符\n')
		self_define(method, hashed)

	#字典爆破
	elif option == 3:
		print('\n选择的爆破方式为 字典爆破\n')
		dic_break(method, hashed)
	

	os.system('pause')

