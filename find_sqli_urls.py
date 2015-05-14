#!/usr/bin/env python
# encoding: utf-8
#!Create By David_Ning

import re,requests,BeautifulSoup
from bs4 import BeautifulSoup
from termcolor import colored
import json,time

sqlmap_server_ip_port = "http://127.0.0.1:9090"
header_dict = {}
header_dict['Content-Type']='application/json'
cant_connect_notice = u'connection timed out to the target URL or proxy. sqlmap is going to retry the request'

def NewScanTask(url_test):
    scan_data = {}
    scan_data['url'] = url_test

    s=requests.get(sqlmap_server_ip_port+"/task/new")
    if s.json()['success'] == True :
        taskid = s.json()['taskid']
        print "[-]new task success.Task_id:"+taskid
    s=requests.post(sqlmap_server_ip_port+"/scan/"+taskid+"/start",data=json.dumps(scan_data),headers=header_dict)
    if s.json()['success'] == True :
        print "[-]task start success."
    s=requests.get(sqlmap_server_ip_port+"/scan/"+taskid+"/status")
    while not (s.json()['status'] == 'terminated'):
        print "[-]sqlinject scanning..."
        time.sleep(20)
        s=requests.get(sqlmap_server_ip_port+"/scan/"+taskid+"/status")

        scan_log_pre = requests.get(sqlmap_server_ip_port+"/scan/"+taskid+"/log")
        scan_log = scan_log_pre.json()[u'log']
        j = 0
        for i in scan_log:
            if cant_connect_notice in i['message']:
                j=j+1
        if j>3:
            print colored("[*]Scan Can't Connect Target!",'yellow')
            break

    if s.json()['status'] == 'terminated':
        print "[+] sqlinject scanning terminated."

    s=requests.get("http://127.0.0.1:9090/scan/"+str(taskid)+"/data")
    if not bool(s.json()[u'data']==[]):
        print colored("[!]HAHA..!I Find SQLinject Url-->"+url_test,'red')
        fd0 = open("SQLinject_Urls.txt",'a')
        fd0.writelines(url_test+'\n')
        fd0.close()

keyword = raw_input("Input some keyword:\n")
search_url_count = raw_input("How many urls you wanna to search?(10<n<100)")
search_url = "http://www.baidu.com/s?wd="+keyword+"&cl=3&rn="+str(search_url_count)+"&pn=3"

r = requests.get(search_url)
soup = BeautifulSoup(r.text)
pre_urls = soup.findAll(attrs={'class':'t'})

waiting_test_urls=[]
re_string = 'http://.*?"'

for pre_url in pre_urls:
    tmp_url = re.findall(re_string,str(pre_url))
    for i in tmp_url:
        i = i[0:-1]
        waiting_test_urls.append(i)
print colored("[+]Find Urls Count:"+str(len(waiting_test_urls)),"green")

test_urls=[]
for i in waiting_test_urls:
    j = requests.get(i)
    test_urls.append(j.url)
test_urls = list(set(test_urls))

for i in test_urls:
    fd1 = open("More_Urls.txt",'a')
    fd1.writelines(i+'\n')
    fd1.close()

for i in waiting_test_urls:
    print "[-]Testing Url:"+i
    try:
        r = requests.get(i,timeout=20)
        testing_url = r.url
        print colored("[+]Find Url:"+testing_url,'green')
        print "[-]Response Code:"+str(r.status_code)
        if r.status_code == 200 and ('?' in testing_url):
            NewScanTask(testing_url)
    except Exception, e:
        print colored("[!]Oh..Time Out!","yellow")

print colored("[$]Job Done!","green")

