# coding=utf-8
"""
@author:Eleven
created on:2018年10月12日
refer to:xunfeng author by wolf
python2
"""
import socket
import binascii
import os


def check(ip, port, timeout):
    negotiate_protocol_request = binascii.unhexlify(
        "00000054ff534d42720000000018012800000000000000000000000000002f4b0000c55e003100024c414e4d414e312e3000024c4d312e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200")
    session_setup_request = binascii.unhexlify(
        "00000063ff534d42730000000018012000000000000000000000000000002f4b0000c55e0dff000000dfff02000100000000000000000000000000400000002600002e0057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(negotiate_protocol_request)
        s.recv(1024)
        s.send(session_setup_request)
        data = s.recv(1024)
        user_id = data[32:34]
        tree_connect_andx_request = "000000%xff534d42750000000018012000000000000000000000000000002f4b%sc55e04ff000000000001001a00005c5c%s5c49504324003f3f3f3f3f00" % ((58 + len(ip)), user_id.encode('hex'), ip.encode('hex'))
        s.send(binascii.unhexlify(tree_connect_andx_request))
        data = s.recv(1024)
        allid = data[28:36]
        payload = "0000004aff534d422500000000180128000000000000000000000000%s1000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00" % allid.encode('hex')
        s.send(binascii.unhexlify(payload))
        data = s.recv(1024)
        s.close()
        if "\x05\x02\x00\xc0" in data:
            return "%s存在ms7-010远程溢出漏洞!!!"%ip
        s.close()
    except:
        return "%s漏洞检查过程中存在异常!!!"%ip

def port_scan():
    ip = raw_input("请输入要进行端口扫描的IP或IP段。\r\n输入格式如:192.168.0.1,192.168.0.0/16:\r\n")
    os.system("%s -p445 %s  -oL port_scan_result.txt"%(masscan_path,ip))
    with open("port_scan_result.txt", 'r') as f:
        for line in f:
            ret = line.split()
            f1 = open("ip_list.txt", 'a+')
            try:
                f1.write(ret[3])
                f1.write('\r\n')
            except:
                pass
            f1.close()
    f.close()


if __name__ == '__main__':
    masscan_path='/root/masscan/bin/masscan'    # 定义masscan路径
    print '-------masscan开始扫描445端口!!!--------------'
    port_scan()
    print '-------开始ms17-010漏洞扫描!!!--------------'
    port = 445  # 定义需要扫描的端口号,默认445
    timeout = 5  # 定义扫描过期时间,默认5s

    with open('ip_list.txt','r') as f1:
        for ip in f1:
            ip=ip.strip()
            scan_result=check(ip,port,timeout)
            f2=open('ms17-010_scan_result.txt','a+')
            if scan_result==None:
                pass
            else:
                f2.write(scan_result)
                f2.write('\r\n')
            f2.close()
    f1.close()
    print('-------扫描完毕!!!--------------')







