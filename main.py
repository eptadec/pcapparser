#!usr/bin/env python
# this code prints Source and Destination IP from the given 'pcap' file

import dpkt
import socket
import os
import time
import glob
import re


def printPcap(pcap):
	strs = []
	vuln_ip = []
	for (ts,buf) in pcap:
			#print(buf)
			eth = dpkt.ethernet.Ethernet(buf)
			ip = eth.data



			#print("protocol =",proto)
			#print(type(ip.data))
			#print(type(dpkt.tcp.TCP))
			#print(isinstance(ip.data, dpkt.tcp.TCP))

			#если tcp данные могут быть:
			if isinstance(ip.data, dpkt.tcp.TCP):

				proto = ip.get_proto(ip.p)
				# read the source IP in src
				src = socket.inet_ntoa(ip.src)
				# read the destination IP in dst
				dst = socket.inet_ntoa(ip.dst)
				# Set the TCP data
				tcp = ip.data
				#записывам только строку юзер агент
				user_agent=find_user_agent(tcp)

				if user_agent!=0:

					strs.append("━" * 116)
					#пишем айпишнегс
					strs.append('Source: ' + src + '\nDestination: ' + dst)

					#пишем версии в юзер агенте
					all_parse, arg_buff = print_version(user_agent)
					#добавляем второй аргумент в конечный список уязвимых айпи
					vuln_ip.append(arg_buff)
					#смотрим не пустой ли он
					if arg_buff!=[]:
						#кидаем в начало для удобства
						#vuln_ip.insert(0,(dst+' | '+src))
						vuln_ip.insert(0,(src+' | '+dst+' s|d'))
					strs.append(all_parse)
					strs.append("━" * 116)
				else:
					strs.append("not find user_agent string ")
	return strs, vuln_ip

#функция для вычленения юзер агента из pcap файла
def find_user_agent(tcp_data):
	tcp = str(tcp_data)
	#print(tcp)
	user_agent_match = re.search(r'User-Agent: ([^\r\\]+)', tcp)
	if user_agent_match:
		user_agent = user_agent_match.group(1).encode('utf-8')
		#print(user_agent)
		return (user_agent)
	else:
		return 0
	# data=(str(user_agent)).split(' ')
	# print(data)

# Функция для поиска версии в строке с учетом возможных старых версий
def find_version(user_agent, app_name, regex_pattern):
    app_version = re.search(regex_pattern, user_agent.decode('utf-8'))
    if app_version:
        return app_name, app_version.group(1)
    else:
        return app_name, "Не удалось определить"

#функция для печатания версий
def print_version(user_agent):
	# Поиск версии операционной системы
	buff=[]
	vuln_ip=[]

	os_version = re.search(r'Windows NT ([\d.]+)', user_agent.decode('utf-8'))
	if os_version:
		os_version = os_version.group(1)
		os_version_number = int(os_version.split('.')[0])
		# здесь проверяется версия винды и её соответсвие нормальному виду
		if os_version_number < 10:
			if os_version == '5.1':
				os_version = "XP" + ' (' + str(os_version) + ')'
			if os_version == '6.0':
				os_version = "VISTA" + ' (' + str(os_version) + ')'
			if os_version == '6.1':
				os_version = "7" + ' (' + str(os_version) + ')'
			if os_version == '6.2':
				os_version = "8" + ' (' + str(os_version) + ')'
			if os_version == '6.3':
				os_version = "8.1" + ' (' + str(os_version) + ')'
			os_version += "<---старая версия!!!"
			#print("|" * 120 + '\n' + "V" * 120)
			buff.append(("|" * 120 + '\n' + "V" * 120))
			vuln_ip.append(f"Версия --->Windows {os_version}")
		#print(f"Версия Windows: {os_version}")
		buff.append(f"Версия Windows: {os_version}")
	else:
		os_version = "Не удалось определить"

	# Список для поиска версий браузеров
	browser_versions = [
		find_version(user_agent, "Chrome", r'Chrome/([\d.]+)'),
		find_version(user_agent, "GOST", r'(Chromium GOST)'),
		find_version(user_agent, "Edge", r'Edg/([\d.]+)'),
		find_version(user_agent, "Yandex", r'YaBrowser/([\d.]+)'),
		find_version(user_agent, "Firefox", r'Firefox/([\d.]+)'),
	]

	# Пометка для старых версий браузеров
	#print("- "*50)
	buff.append("- " * 44)
	for app, version in browser_versions:
		#print(type(version))
		if version != "Не удалось определить":

			#с гостом лень чето придумывать
			if app == "GOST":
				version += "G!!!!!!!!!!!!"

			elif app == "Chrome":
				major_version = re.match(r'^\d+',version).group()
				if int(major_version) < 114:
					version += "<---старая версия!!!"
					#print("|" * 110 +'\n'+"V"* 110)
					buff.append("|" * 110 +'\n'+"V"* 110)
					vuln_ip.append(f"Версия --->{app}: {version}")

			elif (app == "Edge"):
				major_version = re.match(r'^\d+', version).group()
				if int(major_version) < 114:
					version += "<---старая версия!!!"
					#print("|" * 110 +'\n'+"V"* 110)
					buff.append("|" * 110 + '\n' + "V" * 110)
					vuln_ip.append(f"Версия --->{app}: {version}")

			elif (app == "Yandex"):
				if int(major_version) < 23:
					version += "<---старая версия!!!"
					#print("|" * 110 +'\n'+"V"* 110)
					buff.append("|" * 110 + '\n' + "V" * 110)
					vuln_ip.append(f"Версия --->{app}: {version}")

			elif (app == "Firefox" ):
				major_version = re.match(r'^\d+', version).group()
				if int(major_version) < 114:
					version += "<---старая версия!!!"
					#print("|" * 110 +'\n'+"V"* 110)
					buff.append("|" * 110 + '\n' + "V" * 110)
					vuln_ip.append(f"Версия --->{app}: {version}")

			#print(f"Версия {app}: {version}")
			buff.append(f"Версия {app}: {version}")
	#print("- " * 50)
	buff.append("- " * 44)
	return buff, vuln_ip

def flatten_list(nested_list):
    flat_list = []
    for item in nested_list:
        if isinstance(item, list):
            flat_list.extend(flatten_list(item))
        else:
            flat_list.append(item)
    return flat_list

def main():


#'''
	folder_path=input("введите путь до папки : ")
	if folder_path == '3':
		print("C:\\Users\\tarasov.is\Downloads")
		folder_path = "C:\\Users\\tarasov.is\Downloads"
	if folder_path == '4':
		print("C:\\Users\\belkov.ai\Downloads")
		folder_path = "C:\\Users\\belkov.ai\Downloads"
	if folder_path == '5':
		print("C:\\Users\\ivanov-pa\Downloads")
		folder_path = "C:\\Users\\ivanov-pa\Downloads"
	if os.path.exists(folder_path):
		print("путь найден")
	else:
		print(f"Путь не сущетсвует \"{folder_path}\" ")
		folder_path = input("введите путь до папки : ")
	start_time = time.time()
	#folder_path="C:\\Users\\tarasov.is\Downloads"
	pcap_files = glob.glob(folder_path + "/*.pcap")
	count_pcapfiles=0
	strs=[]
	vuln_ip_list=[]
	for pcap_file in pcap_files:
		count_pcapfiles+=1
		strs.append("\n" + pcap_file)
		f = open(pcap_file, 'rb')
		pcap = dpkt.pcap.Reader(f)
		all_parse, vuln_ip = printPcap(pcap)
		if vuln_ip != [] and vuln_ip !=[[]]:
			print(f"{vuln_ip}\n{pcap_file}\n")
			vuln_ip_list.append(vuln_ip)
		strs.append(all_parse)
		f.close()

	flat_result=flatten_list(strs)
	output_file="PARSER_LOG.txt"

	with open(output_file,'w',encoding='utf-8') as txt_file:
		for item in flat_result:
			txt_file.write(item+'\n')

	flat_vuln_ip_list = flatten_list(vuln_ip_list)
	output_vuln_ip_list = "PARSER_vuln_ip.txt"

	with open(output_vuln_ip_list,'w',encoding='utf-8') as txt_file:
		for item in flat_vuln_ip_list:
			txt_file.write(item+'\n')




	print(f"--- {count_pcapfiles} pcap files in {(time.time() - start_time)} seconds ---")
	input("нажмите для завершения")
'''
	script_directory = os.path.dirname(os.path.abspath(__file__))
	#f = open('13.pcap','rb')
	#script_directory="C:\\Users\\tarasov.is\Downloads"
	for filename in os.listdir(script_directory):
		if filename.endswith('.pcap'):
			print("\n"+filename)
			f = open(filename, 'rb')
			pcap = dpkt.pcap.Reader(f)
			printPcap(pcap)
			f.close()
'''



if __name__ == '__main__':
	main()
