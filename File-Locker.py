import tkinter
from Crypto.Cipher import AES
from Crypto.Hash import SHA256 as SHA
from os import path
from Crypto import Random
from tkinter import *
from tkinter import filedialog, messagebox
import tkinter.scrolledtext
import tkinter.ttk as ttk
import easygui
from os.path import getsize

KSIZE = 2048

class myAES():
    def __init__(self, keytext, ivtext):
        hash = SHA.new()
        hash.update(keytext.encode('utf-8'))
        key = hash.digest()
        global bit_len
        self.key = key[:bit_len]

        hash.update(ivtext.encode('utf-8'))
        iv = hash.digest()
        self.iv = iv[:16]

    def makeEncInfo(self, filename):
        fillersize = 0
        filesize = path.getsize(filename)
        
        if filesize%16 != 0:
            fillersize = 16-filesize%16
            
        filler = '0'*fillersize
        header = '%d' %(fillersize)
        gap = 16-len(header)
        header += '#'*gap

        return header, filler

    def enc(self, filename):

        process_bar.set(0)
        process_area.update()

        encfile = filedialog.asksaveasfilename(
            initialdir='path',
            title='Select File',
            filetypes=(('txt files', '*.txt'),
                ('all files', '*.*')))
        print(encfile)
        encfilename = encfile
        header, filler = self.makeEncInfo(filename)
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)

        h = open(filename, 'rb')
        hh = open(encfilename, 'wb+')

        enc = header.encode('utf-8')
        content = h.read(KSIZE)
        content = enc + content
        size = getsize(filename)
        process = 0
        while content:
            if len(content) < KSIZE:
                content += filler.encode('utf-8')

            enc = aes.encrypt(content)
            hh.write(enc)
            process += len(content)
            percent = int(((process/1024)/(size/1024))*100)
            if percent%5 == 0:
                process_bar.set(percent)
                process_area.update()


            content = h.read(KSIZE)
            
        h.close()
        hh.close()
        process_bar.set(100)
        process_area.update()

            
    def dec(self, encfilename):

        process_bar.set(0)
        process_area.update()

        #dec_filename = input("Decrypted File Name : ")
        decfile = filedialog.asksaveasfilename(
            initialdir='path',
            title='Select File',
            filetypes=(('txt files', '*.txt'),
                ('all files', '*.*')))

        filename = decfile
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)

        h = open(filename, 'wb+')
        hh = open(encfilename, 'rb')

        content = hh.read(16)
        dec = aes.decrypt(content)
        header = dec.decode()
        fillersize = int(header.split('#')[0]) 

        content = hh.read(KSIZE)
        size = getsize(encfilename)
        process = 0
        while content:
            dec = aes.decrypt(content)
            if len(dec) < KSIZE:
                if fillersize != 0:
                    dec = dec[:-fillersize]
            h.write(dec)

            process += len(dec)
            percent = int(((process/1024)/(size/1024))*100)
            if percent%5 == 0:
                process_bar.set(percent)
                process_area.update()
            
            content = hh.read(KSIZE)
        h.close()
        hh.close()

        process_bar.set(100)
        process_area.update()

              
def enc_file():
        file = filedialog.askopenfile(
            initialdir='path',
            title='Select File',
            filetypes=(('txt files', '*.txt'),
                ('all files', '*.*')))

        filename = file.name
        info_area.config(state='normal')
        if applied_language == 'en':
            info_area.insert('end',f"\nYou Selected {filename} to Encrypt\n")
        if applied_language == 'kr':
            info_area.insert('end',f"\n{filename}가 암호화할 파일로 선택 되었습니다.\n")
        info_area.config(state='disabled')

        if applied_language == 'en':
            keytext = easygui.enterbox("Secret Key for Encryption", 'File Keeper')
        if applied_language == 'kr':
            keytext = easygui.enterbox("암호화를 위한 비밀번호를 입력하세요", 'File Keeper')

 
        myCipher = myAES(keytext, ivtext)

        myCipher.enc(filename)
        info_area.config(state='normal')
        if applied_language == 'en':
            info_area.insert('end',filename + " is Encrypted\n")
            messagebox.showinfo("Encryption Completed", "The Encryption is successfully completed.")
        if applied_language == 'kr':
            info_area.insert('end',filename + "가 암호화 되었습니다.\n")  
            messagebox.showinfo("암호화 완료", "암호화가 성공적으로 완료되었습니다.")  
        info_area.config(state='disabled')
    
def dec_file():
    file = filedialog.askopenfile(
        initialdir='path',
        title='Select File',
        filetypes=(('txt files', '*.txt'),
            ('all files', '*.*')))

    encfilename = file.name
    filename = file.name
    info_area.config(state='normal')
    if applied_language == 'en':
        info_area.insert('end',f"\nYou Selected {filename} to Decrypt\n")
    if applied_language == 'kr':
        info_area.insert('end',f"\n{filename}가 복호화할 파일로 선택 되었습니다.\n")
    info_area.config(state='disabled')

    if applied_language == 'en':
        keytext = easygui.enterbox("Secret Key for Decryption", 'File Keeper')
    if applied_language == 'kr':
        keytext = easygui.enterbox("복호화를 위한 비밀번호를 입력하세요", 'File Keeper')

    myCipher = myAES(keytext, ivtext)

    myCipher.dec(encfilename)
    info_area.config(state='normal')
    if applied_language == 'en':
        info_area.insert('end',filename + " is Decrypted\n")
        messagebox.showinfo("Decryption Completed", "The Decryption is successfully completed.")
    if applied_language == 'kr':
        info_area.insert('end',filename + "가 복호화 되었습니다.\n")
        messagebox.showinfo("복호화 완료", "복호화가 성공적으로 완료되었습니다.")    
    info_area.config(state='disabled')

bit_len_list = [16,24,32]
global bit_len
bit_len = 32

languages_list = ['en', 'kr']
global applied_language
applied_language = 'en'

ivtext = 'File_Crypto_system_iv_text_2021_11_16'  

root = Tk()

root.title("File Keeper")
root.geometry("540x300+100+100")
root.resizable(False, False)
root.iconbitmap('./icons/main.ico')

info_area=tkinter.scrolledtext.ScrolledText(root, width= 73, height=16)
info_area.place(x=10, y= 10)
info_area.insert('end', '                          --- File Keeper ---\n                                                          Created by Bae')
info_area.insert('end','                                                           version 1.1\n')
info_area.insert('end',f'The current key length is {bit_len*8}bits.\n')
info_area.config(state="disabled")


def language_changer(x):
    global applied_language, lan_b_x
    applied_language = languages_list[x]
    if applied_language == 'en':
        messagebox.showinfo("Setting Applied", "Language change to Englisgh is completed")
        enc_b_text.set("Encryption")
        dec_b_text.set("Decryption")
        lan_b_text.set('Change Language')
        close_text.set('Close')
        setting_b_text.set("Key length setting")
        #lan_b_x.set(370)
        info_label_text.set("File Keeper implements file encryption and decryption using the AES encryption algorithm.\nHere you can set the key length of the AES.\nThe longer the key length, the better security strength it supports, but it takes more time.\nThe default setting is 256 bits.")

    if applied_language == 'kr':
        messagebox.showinfo("설정완료", "언어가 한국어로 변경되었습니다.")
        enc_b_text.set("암호화")
        dec_b_text.set("복호화")
        lan_b_text.set('언어 변경')
        close_text.set('닫기')
        setting_b_text.set("키 길이 설정")
        #lan_b_x.set(400)
        info_label_text.set("File Keeper는 AES암호화 알고리즘을 사용하여 파일 암호화와 복호화를 구현합니다.\n여기서 AES알고리즘에 사용될 키 길이를 설정할 수 있습니다.\n키 길이가 길어질수록 더 강력한 보안이 가능하지만 시간이 더 걸립니다.\n기본 설정은 256비트입니다.")

enc_b_text = tkinter.StringVar()
enc_b_text.set("Encryption")
dec_b_text = tkinter.StringVar()
dec_b_text.set("Decryption") 

close_text = tkinter.StringVar()
close_text.set('Close')

enc_b = Button(root, textvariable=enc_b_text, width= 20, height=1, command=enc_file)
dec_b = Button(root, textvariable=dec_b_text , width= 20, height=1, command=dec_file)


enc_b.place(x = 10, y = 230)
dec_b.place(x = 10, y = 260)

process_bar = DoubleVar()
process_area = ttk.Progressbar(root, maximum=100, length=350, variable=process_bar)
process_area.place(x = 180, y = 230)


def bit_changer(x):
    global bit_len
    bit_len = bit_len_list[x]
    messagebox.showinfo("Setting Applied", f"Key length is {bit_len*8}bits now")
    info_area.config(state='normal')
    info_area.insert('end',f"\nThe current key length is {bit_len*8}bits.\n")
    info_area.config(state='disabled')

info_label_text = tkinter.StringVar()
info_label_text.set("File Keeper implements file encryption and decryption using the AES encryption algorithm.\nHere you can set the key length of the AES.\nThe longer the key length, the better security strength it supports, but it takes more time.\nThe default setting is 256 bits.")

def setting():
    settingwin = tkinter.Toplevel(root)
    settingwin.title("Key Length Setting")
    settingwin.geometry("540x150")
    settingwin.resizable(False, False)
    settingwin.iconbitmap('./icons/setting.ico')

    bit128_b = tkinter.Button(settingwin, text="128bit", width=10, height=2,command=lambda x = 0:bit_changer(x))
    bit192_b = tkinter.Button(settingwin, text="192bit", width=10, height=2,command=lambda x = 1:bit_changer(x))
    bit256_b = tkinter.Button(settingwin, text="256bit", width=10, height=2,command=lambda x = 2:bit_changer(x))
    info_label = tkinter.Label(settingwin, textvariable=info_label_text)
    confirm_b = tkinter.Button(settingwin, textvariable=close_text, command=settingwin.destroy)
    info_label.pack()
    bit128_b.place(x= 110, y= 80)
    bit192_b.place(x= 230, y= 80)
    bit256_b.place(x= 350, y= 80)
    confirm_b.place(x= 490, y= 120)


def languages():
    language_win = tkinter.Toplevel(root)
    language_win.title("Language Setting")
    language_win.geometry("265x150")
    language_win.resizable(False, False)
    #language_win.iconbitmap('')

    languages_check_1 = Button(language_win, width = 10, height = 2, text='English', command=lambda x = 0:language_changer(x))
    languages_check_1.place(x=40,y=40)

    languages_check_2 = Button(language_win, width = 10, height = 2, text='Korean', command=lambda x = 1:language_changer(x))
    languages_check_2.place(x=150,y=40)

    confirm_b = tkinter.Button(language_win, textvariable=close_text, command=language_win.destroy)
    confirm_b.place(x=210, y=110)
    #lang_apply_b = Button(language_win, text='Apply', command=language_changer(x))
    #lang_apply_b.pack()

setting_b_text = tkinter.StringVar()
setting_b_text.set("Key length setting")
setting_b = tkinter.Button(root, textvariable=setting_b_text, command=setting)

lan_b_text = tkinter.StringVar()
lan_b_text.set('Change Language')
lan_b = tkinter.Button(root, textvariable=lan_b_text, command=languages)
setting_b.place(x=420, y= 260)

#lan_b_x = tkinter.IntVar()
#lan_b_x.set(370)
lan_b.place(x=310, y=260)

root.mainloop()



