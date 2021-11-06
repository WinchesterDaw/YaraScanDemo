from PySide2.QtWidgets import QApplication,QMainWindow,QPushButton,QPlainTextEdit,QLineEdit
import os
import hashlib
import csv
import yara

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


def get_files(paths,filenames):
    try:
      file_list=os.listdir(paths)
      file_list=list(map(lambda x:get_path(paths,x),file_list))#找到所有文件的绝对路径
      f_names=list(filter(os.path.isfile,file_list))#找到当前目录下的文件
      names.extend(f_names)#存入names
      d_names=list(filter(os.path.isdir,file_list))#找出当前目录下文件夹名
      go=list(map(lambda x:get_files(get_path(paths,x),filenames),d_names))
    except PermissionError:
      print ("无法打开文件夹 "+paths)
       
def get_csv(paths,filenames):
    f = open('1.csv','w',encoding='utf-8e')
    csv_writer = csv.writer(f)
    csv_writer.writerow(["文件","md5","sha256"])
    ex =list( map(lambda x:csv_writer.writerow([x,get_md5(x),get_sha256(x)]) ,names))
    f.close()
names=[];
def run(rulepath,path,names):
   # path = 'D:/malware'#恶意软件目录，可更改
   if(path=='None' or rulepath=="None"):
         textEdit.setPlainText('文件路径为空')
         textEdit.setPlainText('文件路径无效')
         return 0
   else: 
      my_file=get_files(path,[])
      names=list(filter(lambda x:x.endswith(".exe"),names))
      #rulepath ="D:/YaraRules"#yara规则目录，可更改
      yararule=get_rules(rulepath)#得到编译后的规则
      ex=list(filter(lambda x:scan(yararule,x),names))#扫描names中的文件得到结果
      for x in ex:
          textOut.insertPlainText(x)

     #以上为功能函数
rulepath='None'
path='None'
def pathIn():#获取用户输入的路径
     global path
     path = textEdit.text()
     textEdit.setPlaceholderText('当前扫描文件路径为'+path)
     textEdit.clear()

def rulepathIn():#获取用户输入的路径
     global rulepath
     path = textEdit.text()
     textEdit.setPlaceholderText('当前导入规则路径为'+path)
     textEdit.clear()

def button0_handle():#点击扫描按钮
    global names
    run(path,names)

app = QApplication([])


window = QMainWindow()
window.resize(500,400)
window.move(300,310)
window.setWindowTitle('恶意文件扫描')

textEdit=QLineEdit(window)
textEdit.setPlaceholderText('请输入文件路径')
textEdit.move(10,25)
textEdit.resize(300,50)
textEdit.returnPressed.connect(pathIn)

textEdit1=QLineEdit(window)
textEdit1.setPlaceholderText('请输入导入规则路径')
textEdit1.move(10,85)
textEdit1.resize(300,50)
textEdit1.returnPressed.connect(rulepathIn)


textOut=QPlainTextEdit(window)
textOut.setPlaceholderText('扫描结果将在此显示')
textOut.move(10,200)
textOut.resize(400,100)


button0=QPushButton('扫描',window)#扫描开始
button0.clicked.connect(button0_handle)
button0.move(350,350)




window.show()
app.exec_()
