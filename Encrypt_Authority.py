# -*- coding: utf-8 -*-
# coding: unicode_escape

import wx
import rsa
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import Crypto.Hash.SHA512
import hashlib 
import base64
from pyDes import des, ECB, PAD_PKCS5
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

class Main_menu(wx.Frame):

    def __init__(self,parent):
        wx.Frame.__init__(self, parent=parent, title='加密与认证',size=(470,250))
        self.panel = wx.Panel(self)
        self.Center()
        # 基本参数设置
        height=25
        pos_x = 160
        # 组件
        self.main_txt_1 = wx.StaticText(self.panel,label="请选择需要进行的操作",pos=(pos_x,20))
        self.button_1 = wx.Button(self.panel, label="消息摘要 ", pos=(pos_x, 50), size=(120, height))
        self.button_2 = wx.Button(self.panel, label="数据对称加密", pos=(pos_x, 90), size=(120, height))
        self.button_3 = wx.Button(self.panel, label="数据非对称加密", pos=(pos_x, 130), size=(120, height))
        self.button_4 = wx.Button(self.panel, label="数字签名与认证", pos=(pos_x, 170), size=(120, height))

        # 绑定事件
        self.button_1.Bind(wx.EVT_BUTTON,self.digest)
        self.button_2.Bind(wx.EVT_BUTTON,self.encrypt_d)
        self.button_3.Bind(wx.EVT_BUTTON,self.encrypt_f)
        self.button_4.Bind(wx.EVT_BUTTON,self.authority)

    def digest(self,event):
        win = Digest(None)
        win.Show()
    def encrypt_d(self,event):
        win = Encrypt_d(None)
        win.Show()
    def encrypt_f(self,event):
        win = Encrypt_f(None)
        win.Show()
    def authority(self,event):
        win = Authority(None)
        win.Show()


class Digest(wx.Frame):
   
    def __init__(self,parent):
        wx.Frame.__init__(self, parent=parent, title='消息摘要',size=(470,550))
        self.panel = wx.Panel(self)
        self.Center()

        self.menu_digest()
        

    def menu_digest(self):
        # 基本参数设置
        height=25
        pos_x=340

        # 基础组件
        self.digest_txt = wx.StaticText(self.panel,label="选择进行摘要的文本",pos=(30,20))# 静态文本
        self.message_path = wx.TextCtrl(self.panel, pos=(30, 50), size=(300, height)) # 动态文本框
        self.button_open = wx.Button(self.panel, label="浏览", pos=(pos_x, 50), size=(90, height)) #按钮

        digest_list = ['MD5', 'SHA1']
        self.digest_chioce = wx.RadioBox(self.panel, label='选择信息摘要算法', pos=(30, 90) ,choices=digest_list,
                                majorDimension=1, style=wx.RA_SPECIFY_ROWS,size=(300,height))
        self.button_digest = wx.Button(self.panel, label="开始", pos=(180, 150), size=(90, height))

        self.digest_txt = wx.StaticText(self.panel,label="摘要",pos=(30,180))
        self.digest_output = wx.TextCtrl(self.panel,pos=(30,200),size=(400, height))
        
        # 绑定事件
        self.button_open.Bind(wx.EVT_BUTTON,self.OnOpenFile)
        self.button_digest.Bind(wx.EVT_BUTTON,self.OnClick)

    def OnOpenFile(self,event):
        # 选择文件对话框，设置选择的文件必须为txt格式
        self.dlg = wx.FileDialog(self, message=u"选择文件", style=wx.FD_OPEN | wx.FD_CHANGE_DIR,
                                     wildcard="Text Files (*.txt)|*.txt")
         # 如果确定了选择的文件，将文件路径写到text1控件
        if self.dlg.ShowModal() == wx.ID_OK:
            self.message_path.AppendText(self.dlg.GetPath())
 
    def OnClick(self,event):
        # 判断文本框内容是否为空
        if self.message_path.GetValue() == "":
            wx.MessageBox("请先设定需要消息摘要的文件", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return
        # 只选择一个文件运行
        if self.digest_chioce.GetSelection() == 0:
            self.digest_MD5()
        if self.digest_chioce.GetSelection() == 1:
            self.digest_SHA()
            
 
    def digest_MD5(self):
        self.digest_output.Clear()

        f = open(self.message_path.GetValue())
        str = f.read()
        f.close()

        m = hashlib.md5()   #创建md5对象
        b = str.encode(encoding = 'utf-8') #将字符串信息转为可用的编码（str——>bytes)
        m.update(b) #传递类字节参数(通常是bytes)更新对象   注意此处update（）会累加 m.update(a); m.update(b)等同m.update(a+b)
        str_md5 = m.hexdigest()#返回摘要值
        self.digest_output.AppendText(str_md5)
        
    def digest_SHA(self,hash_algorithm = Crypto.Hash.SHA512):
        self.digest_output.Clear()

        f = open(self.message_path.GetValue())
        str = f.read()
        f.close()

        m = hashlib.sha1()
        b = str.encode(encoding = 'utf-8')
        m.update(b) #传递类字节参数(通常是bytes)更新对象 
        str_sha1 = m.hexdigest()#返回摘要值
        self.digest_output.AppendText(str_sha1)
        

class Encrypt_d(wx.Frame):
   
    def __init__(self,parent):
        wx.Frame.__init__(self, parent=parent, title='对称加密',size=(470,550))
        self.panel = wx.Panel(self)
        self.Center()
        self.menu_encrypt_d()

    def menu_encrypt_d(self):
        # 基本参数设置
        height=25
        pos_x_1=30
        pos_x_2=340

        # 基础组件
        encrypt_d_list = ['DES', 'AES']
        self.encrypt_d_chioce = wx.RadioBox(self.panel, label='选择对称加密算法', pos=(pos_x_1,20) ,choices=encrypt_d_list,
                                majorDimension=1, style=wx.RA_SPECIFY_ROWS,size=(300,height))

        self.encrypt_d_txt = wx.StaticText(self.panel,label="请输入密钥",pos=(pos_x_1,100))
        self.encrypt_d_key = wx.TextCtrl(self.panel,pos=(pos_x_1,120),size=(400, height))

        self.encode_txt = wx.StaticText(self.panel,label="选择进行加密的文件",pos=(pos_x_1,240))
        self.encrypt_path = wx.TextCtrl(self.panel, pos=(pos_x_1, 260), size=(300, height))
        self.button_open_1 = wx.Button(self.panel, label="浏览", pos=(pos_x_2, 260), size=(90, height))
        self.button_encode = wx.Button(self.panel,label="加密", pos=(pos_x_2/2,300), size=(90, height))

        self.decode_txt = wx.StaticText(self.panel,label="选择进行解密的文件",pos=(pos_x_1,360))
        self.decrypt_path = wx.TextCtrl(self.panel, pos=(pos_x_1, 380), size=(300, height))
        self.button_open_2 = wx.Button(self.panel, label="浏览", pos=(pos_x_2, 380), size=(90, height))
        self.button_decode = wx.Button(self.panel,label="解密", pos=(pos_x_2/2,420), size=(90, height))

        # 绑定事件
        self.button_open_1.Bind(wx.EVT_BUTTON,self.open_1)
        self.button_open_2.Bind(wx.EVT_BUTTON,self.open_2)
        self.button_encode.Bind(wx.EVT_BUTTON,self.encode)
        self.button_decode.Bind(wx.EVT_BUTTON,self.decode)

    def encode(self,event):
        if(self.encrypt_d_key.GetValue() == ""):
            wx.MessageBox("请先输入密钥", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return
        if(self.encrypt_path.GetValue() == ""):
            wx.MessageBox("请先选择需要加密的文件", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return
        if self.encrypt_d_chioce.GetSelection()==0:
            self.des_encode()
        else :
            self.aes_encode()
        
    def des_encode(self):
        # 读取文件信息
        with open(self.encrypt_path.GetValue(),'r') as f:
            s = f.read()
        # 加密
        key = self.encrypt_d_key.GetValue()
        content = self.des_encrypt(key.ljust(8,'0'),s)
        # 将加密后的字符串写入文件
        with open('DES_Encode.txt','w') as f:
            f.write(content)
        if True:
            wx.MessageBox("加密成功！\n请在文件目录下查看", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return
    def aes_encode(self):
        # 初始化
        key = self.encrypt_d_key.GetValue()
        pc = PrpCrypt(key.ljust(16,'0'))
        # 读取文件信息
        with open(self.encrypt_path.GetValue(),'r') as f:
            s = f.read() 
        # 加密
        e = pc.encrypt(s)  
        # 将加密后的字符串写入文件
        with open('AES_Encode.txt','w') as f:
            f.write(e.decode())
        if True:
            wx.MessageBox("加密成功！\n请在文件目录下查看", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return

    def decode(self,event):
        if(self.encrypt_d_key.GetValue() == ""):
            wx.MessageBox("请先输入密钥", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return
        if(self.decrypt_path.GetValue() == ""):
            wx.MessageBox("请先选择需要解密的文件", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return
        if self.encrypt_d_chioce == 0:
            self.des_decode()
        else :
            self.aes_decode()

    def des_decode(self):
        # 读取文件信息
        with open(self.decrypt_path.GetValue(),'r') as f:
            s = f.read()
        # 解密
        key = self.encrypt_d_key.GetValue()
        content = self.des_decrypt(key.ljust(8,'0'),s)
        # 将加密后的字符串写入文件
        with open('DES_Decode.txt','w') as f:
            f.write(content)
        if True:
            wx.MessageBox("解密成功！\n请在文件目录下查看", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return

    def aes_decode(self):
        # 初始化
        key = self.encrypt_d_key.GetValue()
        pc = PrpCrypt(key.ljust(16,'0'))
        # 读取文件信息
        with open(self.decrypt_path.GetValue(),'r') as f:
            s = f.read()
        # 解密
        d = pc.decrypt(s.encode())
        # 将解密后的字符串写入文件
        with open('AES_Decode.txt','w') as f:
            f.write(d)
        if True:
            wx.MessageBox("解密成功！\n请在文件目录下查看", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return

    def open_1(self,event):
        self.encrypt_path.Clear()
        # 选择文件对话框，设置选择的文件必须为txt格式
        dlg = wx.FileDialog(self, message=u"选DES_择文件", style=wx.FD_OPEN | wx.FD_CHANGE_DIR,
                                     wildcard="Text Files (*.txt)|*.txt")
         # 如果确定了选择的文件，将文件路径写到控件
        if dlg.ShowModal() == wx.ID_OK:
            self.encrypt_path.AppendText(dlg.GetPath())

    def open_2(self,event):
        self.decrypt_path.Clear()
        # 选择文件对话框，设置选择的文件必须为txt格式
        dlg = wx.FileDialog(self, message=u"选择文件", style=wx.FD_OPEN | wx.FD_CHANGE_DIR,
                                     wildcard="Text Files (*.txt)|*.txt")
         # 如果确定了选择的文件，将文件路径写到控件
        if dlg.ShowModal() == wx.ID_OK:
            self.decrypt_path.AppendText(dlg.GetPath())

    def des_encrypt(self,KEY,s):
        """
        DES 加密
        :param s: 原始字符串
        :return: 加密后字符串，16进制
        """
        secret_key = KEY
        iv = secret_key
        k = des(secret_key, ECB, iv, pad=None, padmode=PAD_PKCS5)
        en = k.encrypt(s.encode('utf-8'), padmode=PAD_PKCS5)
        return str(base64.b64encode(en),'utf-8')

    def des_decrypt(self,KEY,s):
        """
        DES 解密
        :param s: 加密后的字符串，16进制
        :return:  解密后的字符串
        """
        secret_key = KEY
        iv = secret_key
        k = des(secret_key, ECB, iv, pad=None, padmode=PAD_PKCS5)
        de = k.decrypt(base64.b64decode(s), padmode=PAD_PKCS5)
        return str(de.decode())

class Encrypt_f(wx.Frame):
   
    def __init__(self,parent):
        wx.Frame.__init__(self, parent=parent, title='非对称加密',size=(470,550))
        self.panel = wx.Panel(self)
        self.Center()
        self.menu_encrypt_f()

    def menu_encrypt_f(self):
        # 基本参数设置
        height=25
        pos_x_1=30
        pos_x_2=340

        # 基础组件
        key_list = ["是", '否']
        self.key_chioce = wx.RadioBox(self.panel, label='是否自动生成密钥对', pos=(pos_x_1, 20) ,choices=key_list,
                                majorDimension=1, style=wx.RA_SPECIFY_ROWS,size=(300,height))
        self.button_key = wx.Button(self.panel, label="确定", pos=(pos_x_2/2,60), size=(90, height))

        self.encrypt_f_txt_P = wx.StaticText(self.panel,label="Public key",pos=(pos_x_1,100))
        self.P_key = wx.TextCtrl(self.panel,pos=(pos_x_1,120),size=(400, height))

        self.encrypt_f_txt_S = wx.StaticText(self.panel,label="Private key",pos=(pos_x_1,160))
        self.S_key = wx.TextCtrl(self.panel,pos=(pos_x_1,180),size=(400, height))

        self.encode_txt = wx.StaticText(self.panel,label="选择进行加密的文件",pos=(pos_x_1,240))
        self.encode_path = wx.TextCtrl(self.panel, pos=(pos_x_1, 260), size=(300, height))
        self.button_open_e = wx.Button(self.panel, label="浏览", pos=(pos_x_2, 260), size=(90, height))
        self.button_encode = wx.Button(self.panel,label="加密", pos=(pos_x_2/2,300), size=(90, height))

        self.decode_txt = wx.StaticText(self.panel,label="选择进行解密的文件",pos=(pos_x_1,360))
        self.decode_path = wx.TextCtrl(self.panel, pos=(pos_x_1, 380), size=(300, height))
        self.button_open_d = wx.Button(self.panel, label="浏览", pos=(pos_x_2, 380), size=(90, height))
        self.button_decode = wx.Button(self.panel,label="解密", pos=(pos_x_2/2,420), size=(90, height))

        # 绑定事件
        self.button_key.Bind(wx.EVT_BUTTON,self.create_key)
        self.button_open_e.Bind(wx.EVT_BUTTON,self.open_e)
        self.button_open_d.Bind(wx.EVT_BUTTON,self.open_d)
        self.button_encode.Bind(wx.EVT_BUTTON,self.encode)
        self.button_decode.Bind(wx.EVT_BUTTON,self.decode)

    def create_key(self,event):
        if self.key_chioce.GetSelection()==0 :
            public_key, private_key = rsa.newkeys(1024)
            public_key = public_key.save_pkcs1().decode()
            private_key = private_key.save_pkcs1().decode()

            with open("public_key.pem",'w') as f:
                f.write(public_key)
            with open("private_key.pem",'w') as f:
                f.write(private_key)
            self.P_key.Clear()
            self.P_key.AppendText(public_key)
            self.S_key.Clear()
            self.S_key.AppendText(private_key)
        else :
            self.P_key.Clear()
            self.S_key.Clear()

    def encode(self,event):
        if(self.P_key.GetValue() == ""):
            wx.MessageBox("请先输入公钥", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return
        public_key = rsa.PublicKey.load_pkcs1(self.P_key.GetValue().encode())
        with open(self.encode_path.GetValue()) as f:
            message = f.read()
        # 由于RSA的特性，一个1024位的密钥只能加密117位字节数据，当数据量超过117位字节的时候，程序就会抛出异常
        content = rsa.encrypt(message.encode('utf-8'), public_key)
        # base64处理
        with open('RSA_Encode.txt','w') as f:
            f.write(str(base64.b64encode(content),'utf-8'))
        if True:
            wx.MessageBox("加密成功！\n请在文件目录下查看", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return

    def decode(self,event):
        if(self.S_key.GetValue() == ""):
            wx.MessageBox("请先输入私钥", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return
        # 获取私钥
        private_key = rsa.PrivateKey.load_pkcs1(self.S_key.GetValue().encode())
        # 打开需要解密的文件
        with open(self.decode_path.GetValue(),'r') as f:
            message = f.read()
        # bas64解密
        s = base64.b64decode(message)
        # 私钥解密
        content = rsa.decrypt(s, private_key)
        with open('RSA_Decode.txt','w') as f:
            f.write(str(content.decode()))
        if True:
            wx.MessageBox("解密成功！\n请在文件目录下查看", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return

    def open_e(self,event):
        self.encode_path.Clear()
        # 选择文件对话框，设置选择的文件必须为txt格式
        dlg = wx.FileDialog(self, message=u"选择文件", style=wx.FD_OPEN | wx.FD_CHANGE_DIR,
                                     wildcard="Text Files (*.txt)|*.txt")
         # 如果确定了选择的文件，将文件路径写到控件
        if dlg.ShowModal() == wx.ID_OK:
            self.encode_path.AppendText(dlg.GetPath())

    def open_d(self,event):
        self.decode_path.Clear()
        # 选择文件对话框，设置选择的文件必须为txt格式
        dlg = wx.FileDialog(self, message=u"选择文件", style=wx.FD_OPEN | wx.FD_CHANGE_DIR,
                                     wildcard="Text Files (*.txt)|*.txt")
         # 如果确定了选择的文件，将文件路径写到控件
        if dlg.ShowModal() == wx.ID_OK:
            self.decode_path.AppendText(dlg.GetPath())


class Authority(wx.Frame):
    def __init__(self,parent):
        wx.Frame.__init__(self,parent = parent ,title = "数字签名与认证",size=(480,550))
        self.panel = wx.Panel(self)
        self.Center()
        self.setupStatusBar()

    def setupStatusBar(self):
        self.menu_SN_AT()

    def menu_SN_AT(self):
        # 基本参数设置
        height=25
        pos_x_1=30
        pos_x_2=340

        # 签名
        self.signature_txt = wx.StaticText(self.panel,label="签名",pos=(220,10))

        self.signature_txt_s = wx.StaticText(self.panel,label="选择存放私钥的文件",pos=(pos_x_1,40))
        self.signature_s_key_path = wx.TextCtrl(self.panel,pos=(pos_x_1,60),size=(300, height))
        self.button_open_1 = wx.Button(self.panel, label="浏览", pos=(pos_x_2, 60), size=(90, height))

        self.signature_txt_d = wx.StaticText(self.panel,label="选择需要签名的文件",pos=(pos_x_1,100))
        self.signature_file_path = wx.TextCtrl(self.panel,pos=(pos_x_1,120),size=(300, height))
        self.button_open_2 = wx.Button(self.panel, label="浏览", pos=(pos_x_2, 120), size=(90, height))

        self.button_signature = wx.Button(self.panel,label="签名", pos=(pos_x_2/2,160), size=(90, height))

        # 认证
        self.authority_txt = wx.StaticText(self.panel,label="认证",pos=(220,260))

        self.authority_txt_p = wx.StaticText(self.panel,label="选择存放公钥的文件",pos=(pos_x_1,280))
        self.authority_p_key_path = wx.TextCtrl(self.panel,pos=(pos_x_1,300),size=(300, height))
        self.button_open_3 = wx.Button(self.panel, label="浏览", pos=(pos_x_2, 300), size=(90, height))

        self.authority_txt_d = wx.StaticText(self.panel,label="选择需要认证的签名",pos=(pos_x_1,340))
        self.authority_key_d = wx.TextCtrl(self.panel,pos=(pos_x_1,360),size=(300, height))
        self.button_open_4 = wx.Button(self.panel, label="浏览", pos=(pos_x_2, 360), size=(90, height))

        self.authority_txt_f = wx.StaticText(self.panel,label="选择需要认证的文件",pos=(pos_x_1,400))
        self.authority_file_path = wx.TextCtrl(self.panel,pos=(pos_x_1,420),size=(300, height))
        self.button_open_5 = wx.Button(self.panel, label="浏览", pos=(pos_x_2, 420), size=(90, height))

        self.button_authority = wx.Button(self.panel,label="认证", pos=(pos_x_2/2,460), size=(90, height))

        # 绑定事件
        self.button_open_1.Bind(wx.EVT_BUTTON,self.OnOpenFile_1)
        self.button_open_2.Bind(wx.EVT_BUTTON,self.OnOpenFile_2)
        self.button_signature.Bind(wx.EVT_BUTTON,self.signature)
        self.button_open_3.Bind(wx.EVT_BUTTON,self.OnOpenFile_3)
        self.button_open_4.Bind(wx.EVT_BUTTON,self.OnOpenFile_4)
        self.button_open_5.Bind(wx.EVT_BUTTON,self.OnOpenFile_5)
        self.button_authority.Bind(wx.EVT_BUTTON,self.authority)

    def OnOpenFile_5(self,event):
        self.authority_file_path.Clear()
        # 选择文件对话框，设置选择的文件必须为txt格式
        dlg = wx.FileDialog(self, message=u"选择文件", style=wx.FD_OPEN | wx.FD_CHANGE_DIR,
                                     wildcard="Text Files (*.txt)|*.txt")
         # 如果确定了选择的文件，将文件路径写到控件
        if dlg.ShowModal() == wx.ID_OK:
            self.authority_file_path.AppendText(dlg.GetPath())

    def OnOpenFile_4(self,event):
        self.authority_key_d.Clear()
        # 选择文件对话框，设置选择的文件必须为txt格式
        dlg = wx.FileDialog(self, message=u"选择文件", style=wx.FD_OPEN | wx.FD_CHANGE_DIR,
                                     wildcard="Text Files (*.txt)|*.txt")
         # 如果确定了选择的文件，将文件路径写到控件
        if dlg.ShowModal() == wx.ID_OK:
            self.authority_key_d.AppendText(dlg.GetPath())

    def OnOpenFile_3(self,event):
        self.authority_p_key_path.Clear()
        # 选择文件对话框，设置选择的文件必须为txt格式
        dlg = wx.FileDialog(self, message=u"选择文件", style=wx.FD_OPEN | wx.FD_CHANGE_DIR,
                                     wildcard="Text Files (*.pem)|*.pem")
         # 如果确定了选择的文件，将文件路径写到控件
        if dlg.ShowModal() == wx.ID_OK:
            self.authority_p_key_path.AppendText(dlg.GetPath())

    def OnOpenFile_2(self,event):
        self.signature_file_path.Clear()
        # 选择文件对话框，设置选择的文件必须为txt格式
        dlg = wx.FileDialog(self, message=u"选择文件", style=wx.FD_OPEN | wx.FD_CHANGE_DIR,
                                     wildcard="Text Files (*.txt)|*.txt")
         # 如果确定了选择的文件，将文件路径写到控件
        if dlg.ShowModal() == wx.ID_OK:
            self.signature_file_path.AppendText(dlg.GetPath())

    def OnOpenFile_1(self,event):
        self.signature_s_key_path.Clear()
        # 选择文件对话框，设置选择的文件必须为txt格式
        dlg = wx.FileDialog(self, message=u"选择文件", style=wx.FD_OPEN | wx.FD_CHANGE_DIR,
                                     wildcard="Text Files (*.pem)|*.pem")
         # 如果确定了选择的文件，将文件路径写到控件
        if dlg.ShowModal() == wx.ID_OK:
            self.signature_s_key_path.AppendText(dlg.GetPath())
    # 签名
    def signature(self,event):
        # 判断文本框内容是否为空
        if self.signature_s_key_path.GetValue() == "":
            wx.MessageBox("请先选择存放私钥的文件", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return
        if self.signature_file_path.GetValue() == "":
            wx.MessageBox("请先设定需要签名的文件", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return
        # 获取私钥
        with open(self.signature_s_key_path.GetValue()) as f:
            private_key = f.read()
        # 获取文件
        with open(self.signature_file_path.GetValue()) as f:
            message = f.read()

        signature = self.rsa_sign(message.encode(encoding='utf-8'), private_key)# 私钥加密

        # 将签名写入文件
        with open('Digital_Sign.txt','wb') as f:
            f.write(signature)
        # 展示签名
        if True:
            wx.MessageBox("签名成功！\n请在文件目录下查看", "提示消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return

    def rsa_sign(self,plaintext, key, hash_algorithm=Crypto.Hash.SHA512):
        """RSA 数字签名"""
        signer = PKCS1_v1_5.new(RSA.importKey(key))
        hash_value = hash_algorithm.new(plaintext)
        return signer.sign(hash_value)

    # 验证
    def authority(self,event):
        # 读取公钥
        with open(self.authority_p_key_path.GetValue()) as f:
            public_key = f.read()
        # 读取文件
        with open(self.authority_file_path.GetValue()) as f:
            message = f.read()
        # 读取签名
        with open('Digital_Sign.txt','rb') as f:
            signature = f.read()
        result = self.rsa_verify(signature, message.encode('utf-8'), public_key)# 公钥解密

        if result == True:
            wx.MessageBox("认证成功", "验证消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return
        else:
            wx.MessageBox("认证错误", "验证消息", wx.OK | wx.YES_DEFAULT) # 提示框
            return

    def rsa_verify(self,sign, plaintext, key, hash_algorithm=Crypto.Hash.SHA512):
        """校验RSA 数字签名"""
        hash_value = hash_algorithm.new(plaintext)
        verifier = PKCS1_v1_5.new(RSA.importKey(key))
        return verifier.verify(hash_value, sign)
class PrpCrypt(object):

    def __init__(self, key):
        self.key = key.encode('utf-8')
        self.mode = AES.MODE_CBC

    # 加密函数，如果text不足16位就用空格补足为16位，
    # 如果大于16当时不是16的倍数，那就补足为16的倍数。
    def encrypt(self, text):
        text = text.encode('utf-8')
        cryptor = AES.new(self.key, self.mode, b'0000000000000000')
        # 这里密钥key 长度必须为16（AES-128）,
        # 24（AES-192）,或者32 （AES-256）Bytes 长度
        # 目前AES-128 足够目前使用
        length = 16
        count = len(text)
        if count < length:
            add = (length - count)
            # \0 backspace
            # text = text + ('\0' * add)
            text = text + ('\0' * add).encode('utf-8')
        elif count > length:
            add = (length - (count % length))
            # text = text + ('\0' * add)
            text = text + ('\0' * add).encode('utf-8')
        self.ciphertext = cryptor.encrypt(text)
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, b'0000000000000000')
        plain_text = cryptor.decrypt(a2b_hex(text))
        # return plain_text.rstrip('\0')
        return bytes.decode(plain_text).rstrip('\0')   
    
class CA(wx.Frame):
   
    def __init__(self,parent):
        wx.Frame.__init__(self, parent=parent, title='数字证书',size=(470,550))
        self.panel = wx.Panel(self)
        self.Center()
        self.setupStatusBar()# 初始化界面

    def setupStatusBar(self):
        self.menu_creat_ca()

    def menu_creat_ca(self):
        print("数字证书")


def main():

    app = wx.App()
    ex = Main_menu(None)
    ex.Show()
    app.MainLoop()


if __name__ == '__main__':
    main()  