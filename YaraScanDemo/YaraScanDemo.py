import os
import hashlib
import csv
import yara
import argparse
import shutil
import sys
num = 0
names=[]

lines=[]#白名单行


def get_path(p,x):#获取文件绝对路径
    return os.path.join(p,x)

def get_rules(path):#获取并编译目录内的yara规则
    filepath ={}
    for index,file in enumerate(os.listdir(path)):
        rupath=os.path.join(path,file)
        key = "rule"+str(index)
        filepath[key]= rupath
    yararule = yara.compile(filepaths=filepath)
    return yararule

def scan (rule,name):
   fp=open (name,'rb')
   matches=rule.match(data=fp.read())
   if len(matches)>0:
      return (name,matches)#输出匹配到的文件路径和字符串
   else :return 


def get_sha256(name):
   with open(name,'rb')as f:
    sha256obj = hashlib.sha256()
    sha256obj.update(f.read())
    hash_value=sha256obj.hexdigest()
    return hash_value
    

def get_md5(name):
   with open(name,'rb')as f:
    md5obj = hashlib.md5()
    md5obj.update(f.read())
    hash_value=md5obj.hexdigest()
    return hash_value


def whitelist(x):
    for line in lines:
        if x==line:
            return False
    return True


def get_files(paths,filenames):
        try:
            file_list = os.listdir(paths)
            file_list = list(map(lambda x: get_path(paths, x), file_list))  # 找到所有文件的绝对路径
            #file_list=list(filter(whitelist,file_list))
            f_names = list(filter(os.path.isfile, file_list))  # 找到当前目录下的文件
            names.extend(f_names)  # 存入names
            d_names = list(filter(os.path.isdir, file_list))  # 找出当前目录下文件夹名
            go = list(map(lambda x: get_files(get_path(paths, x), filenames), d_names))
        except (PermissionError,FileNotFoundError):
            pass


def run(rulepath,path,names):
      my_file=get_files(path,[])
      #names=list(filter(lambda x:x.endswith(".fas") or x.endswith(".lsp") or x.endswith(".bak") ,names))
      #rulepath ="D:/YaraRules"#yara规则目录，可更改
      yararule=get_rules(rulepath)#得到编译后的规则
      names=list(filter(lambda x:scan(yararule,x),names))#扫描names中的文件得到结果
      with open('Log.txt', 'a') as f:
          for name in names:
              global num
              temp = num
              curname = name + str(temp) + ".bak"
              try:
                  os.rename(name, curname)
                  shutil.copy(curname, "./isolation")
              except  (FileNotFoundError,PermissionError):
                   pass
              f.write(curname + '\n')
              num = num + 1
def delete():
    with open("Log.txt", 'r+') as f:
        f.truncate(0)

rulepath=os.path.abspath('./rules')
path='D:/abc'
if __name__ =="__main__":
    parser =argparse.ArgumentParser(description='yarScan')
    parser.add_argument('-m', help='Path to scan for malware')
    args = parser.parse_args()
    if args.m:
         if os.path.isfile(args.m):
          sys.exit(0)
         else:
          path=args.m
    #f=open('whitelist.txt')
    #lines=f.readlines()
    #f.close()
    delete()
    if not path == 'None':
     try:
      run(rulepath,path,names)
     except (FileNotFoundError,PermissionError):
         pass
     print("success")
    #dirpath=os.path.abspath("isolation")

 
            
        
