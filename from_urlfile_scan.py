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
        time.sleep(8)
        s=requests.get(sqlmap_server_ip_port+"/scan/"+taskid+"/status")

        scan_log_pre = requests.get(sqlmap_server_ip_port+"/scan/"+taskid+"/log")
        scan_log = scan_log_pre.json()[u'log']
        j = 0
        for i in scan_log:
            if cant_connect_notice in i['message']:
                j=j+1
        if j>6:
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

file_name = raw_input("Input URLs File\n")
fd = open("file_name",'r')
waiting_test_urls = fd.readlines()
fd.close()

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

