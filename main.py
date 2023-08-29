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
	domain_name = []
	for (ts,buf) in pcap:
			#print(buf)

			try:
				eth = dpkt.ethernet.Ethernet(buf)
				ip = eth.data
			# read the destination IP in dst
			except:
				continue

			try:
				src = socket.inet_ntoa(ip.src)

				dst = socket.inet_ntoa(ip.dst)
			except:
				pass
			#print("protocol =",proto)
			#print(type(ip.data))
			#print(type(dpkt.tcp.TCP))
			#print(isinstance(ip.data, dpkt.tcp.TCP))
			#print(type(ip.data))
			#print(type(dpkt.dns.DNS))
			try:
				udp = ip.data
			except:
				pass
			temp_buff=[]
			try:
				dns = dpkt.dns.DNS(udp.data)
				#print("dns распознан")
				for qname in dns.qd:
					temp_buff.append(src)
					temp_buff.append(dst)
					temp_buff.append(qname.name)
					domain_name.extend(temp_buff)

					#print("domain name:", domain_name)
			except:
				pass


			#если tcp данные могут быть:
			if isinstance(ip.data, dpkt.tcp.TCP):


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
	return strs, vuln_ip, domain_name

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

#делает из [ [],[[],[]] ] -> [ [], [], [] ]
def flatten_list(nested_list):
    flat_list = []
    for item in nested_list:
        if isinstance(item, list):
            flat_list.extend(flatten_list(item))
        else:
            flat_list.append(item)
    return flat_list

def check_domain(domain_list):
	print(domain_list)
def main():

	indicator = 1
#'''
	while(indicator == 1):
		folder_path=input("(введите 1 для выхода) введите путь до папки : ")

		if folder_path == '1':
			print("Выход...")
			return 0
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
			indicator = 0
			print("путь существует")
			break
		else:
			print(f"Путь не найден \"{folder_path}\" ")


	#НАЧАЛО ПРОГРАММЫ -------------------------------------------------------------
	indicator = '3';
	while (indicator == '3' or indicator == '4'):
		start_time = time.time()
		print("\n--- --- start parse --- ---\n")
		#folder_path="C:\\Users\\tarasov.is\Downloads"

		pcap_files = glob.glob(folder_path + "/*.pcap")

		path = folder_path
		#сортиврока по дате измнения файла для корректного вывода
		#file_list = os.listdir(path)

		file_list = pcap_files
		full_list = [os.path.join(path, i) for i in file_list]
		time_sorted_list = sorted(full_list, key = os.path.getmtime)

		pcap_files = time_sorted_list

		#cписки для хранения всякого
		count_pcapfiles=0
		strs=[]#этот cписок для основного лога
		vuln_ip_list=[]#этот cписок для айпи с уязвимыми версиями
		vuln_ip_list_unic=[]
		domain_name_list=[]#этот cписок для всех доменных имен
		domain_name_list_unic=[]#этот cписок без повторных доменов


	#основной цикл с вызовом функий и записью файла
		for pcap_file in pcap_files:
			mtime=(os.path.getmtime(pcap_file))
			filechange_time=time.ctime(mtime)
			#print(filechange_time)
			#print(pcap_file)
			count_pcapfiles+=1
			strs.append("\n" + pcap_file)

			f = open(pcap_file, 'rb')
			try:
				pcap = dpkt.pcap.Reader(f)
				#вызов основной функции
				all_parse, vuln_ip, ip_and_domain = printPcap(pcap)
			except:
				continue

			#общий лог
			strs.append(all_parse)
			f.close()

			#составляем список если нашли домены
			if ip_and_domain !=[]:
				#если вернулся не пустой список, то там лежит строка с доменом, её потом добавим в список для ВСЕХ доменов
				string_for_print=(ip_and_domain[0]+" | "+ip_and_domain[1]+" s|d: "+ip_and_domain[2])
				domain_name_list.append(string_for_print)

				# ищем айди в имени файла, без повторок на конце !!! -> "(1),(2)"
				match = re.search(r'id-(\d+)\.pcap', pcap_file)
				# если нашли, то добавляем айди в результирующий список
				if match:

					domain_name_list.append(match.group(1))
					#если эта строка найдется в массиве с уникальными доменами, то она не уникальна и к уникальным не заносим
					if (string_for_print not in domain_name_list_unic):
						domain_name_list_unic.append(string_for_print)
						domain_name_list_unic.append(match.group(1))

			buff2=''

			#чекаем чтобы массив с айпи был не пустой
			if vuln_ip != [] and vuln_ip !=[[]]:
				#т.к vuln_ip это всегда ['',['']] или ['',['','',''...]]
				#то надо перебрать вложенный список с уязвимыми версиями:
				for item in vuln_ip[1]:
					#заодно сразу лепим сплошную строку из уязвимостей чтобы заюзать not in (я гений знаю)
					buff2 = (buff2+item)
				#и также к строке лепим айпишники
				string_for_compare = (vuln_ip[0] + ": " + buff2)
				#ну и т.к я выбираю как строки будут выглядить, то можно между собой их сравнить
				#если строка попадается в списке с уникальными, то она не уникальна(х2 гений)

				if (string_for_compare not in vuln_ip_list_unic):
					#если строки нет, то заносим в список с уникальными
					vuln_ip_list_unic.append(string_for_compare)
					# выводим колбасу из айпи и уязвимостей
					print(f"{vuln_ip}\n{pcap_file}\n")
					#ну и айди на всякий случай тоже следом пришлепываем
					match = re.search(r'id-(\d+)\.pcap', pcap_file)
					if match:
						vuln_ip_list_unic.append(match.group(1))

				#print(f"{vuln_ip}\n{pcap_file}\n")
				#на всякий случай еще один список, без сравнений по уникальности
				vuln_ip_list.append(vuln_ip)

		#дальше записи в файлики всех списков с найденными преколами

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

		flat_vuln_ip_list_unic = flatten_list(vuln_ip_list_unic)
		output_vuln_ip_list_unic = "PARSER_UNIC_vuln_ip.txt"

		with open(output_vuln_ip_list_unic, 'w', encoding='utf-8') as txt_file:
			for item in flat_vuln_ip_list_unic:
				txt_file.write(item + '\n')

		flat_domain_name_list = flatten_list(domain_name_list)
		output_domain_name_list = "PARSER_domain_names.txt"

		with open(output_domain_name_list,'w',encoding='utf-8') as txt_file:
			for item in flat_domain_name_list:
				txt_file.write(item+'\n')

		flat_domain_name_list_unic = flatten_list(domain_name_list_unic)
		output_domain_name_list_unic = "PARSER_UNIC_domain_names.txt"

		with open(output_domain_name_list_unic,'w',encoding='utf-8') as txt_file:
			for item in flat_domain_name_list_unic:
				txt_file.write(item+'\n')


		print(f"--- {count_pcapfiles} pcap files in {(time.time() - start_time)} seconds ---")
		if indicator != '4':
			indicator=input("нажмите 1 для завершения, 3 для повтороной проверки, 4 для входа в цикл")
		print(indicator)
		if indicator == '1':
			return 0
		if indicator == '4':
			time.sleep(60)
			os.system('cls||clear')

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
