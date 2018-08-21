import hashlib
import os
import copy

print('\n本程序可通过导入字典文件可对不同哈希值进行爆破，字典可使用字典生成工具生成')
print('可针对md5 sha1 sha224 sha256 sha384 sha512六种常见类型进行爆破')
print('可自动对哈希类型进行判断\n')

flag = 1
while flag:
	try:
		hashed = input('\n请输入将要爆破的哈希值：\nPlease input the hash code:')
		length = len(hashed)
		if length not in [32,40,56,64,96,128]:
			print('\n无效哈希值\nThe hash value is unavailible.\n')
			continue
		flag = 0
	except Exception as e:
		print(e)


while flag == 0:
	try:
		dic = input('\n请输入你想导入的字典：\nPlease input the name of your directory:')
		with open(dic,'r') as f:
			a = f.readlines()
		flag = 1
	except:
		print('No such directory.Try again!')

#print(a)

if length == 32:
	ha = hashlib.md5()
elif length == 40:
	ha = hashlib.sha1()
elif length == 56:
	ha = hashlib.sha224()
elif length == 64:
	ha = hashlib.sha256()
elif length == 96:
	ha = hashlib.sha384()
elif length == 128:
	ha = hashlib.sha512()

'''
名称 	描述							长度
md5(…) 	利用md5算法加密				32
sha1(…) 	利用sha1算法加密         40
sha224(…) 	利用sha224算法加密		56
sha256(…) 	利用sha256算法加密		64
sha384(…) 	利用sha384算法加密		96
sha512(…) 	利用sha512算法加密		128
'''

for i in a:
	print(i[:-1])
	ha_ = ha.copy()
	#ha = hashlib.sha224()		#sha224可根据实际情况修改
	ha_.update(i[:-1].encode("utf-8"))	#Unicode-objects must be encoded before hashing
	print(ha_.hexdigest())
	
	if ha_.hexdigest() == hashed:
		print('\nFOUND:', i[:-1], '\n')
		flag = 0
		break

if flag == 1:print('\n字典中不包含原明文\nNOT FOUND\n')
os.system('pause')

