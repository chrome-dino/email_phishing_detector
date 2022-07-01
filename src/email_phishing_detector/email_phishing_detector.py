from pyshorteners import Shortener
import virustotal_python
from virus_total_apis import PublicApi as VirusTotalPublicApi
from base64 import urlsafe_b64encode
import email
from email import policy
from email.parser import BytesParser
import re
import hashlib
import os

class EmailPhishingDetector():

    def __init__(self, file='', key='', mode='', password=''):
        # Intialize member variables
        self.file = file
        self.key = key
        self.mode = mode
        self.password = password


    def expand_links(self,links):
        if self.mode == 'tinyurl':
            s = Shortener()
        elif self.mode == 'bitly':
            s = Shortener(api_key=self.password)
        final = []
        for link in links:
            if self.mode == 'tinyurl':
                expanded_link = s.tinyurl.expand(link)
                final.append(expanded_link)
            elif self.mode == 'bitly':
                expanded_link = s.bitly.expand(link)
                final.append(expanded_link)
            else:
                final.append(link)
        return final
       
    @staticmethod
    def get_hash():
        hashes = []

        for root, dirs, files in os.walk('.\\email_phishing_detector\\src\\email_phishing_detector\\attachments'):
            for file in files:
                if file == 'README':
                    continue
                hashes.append({'filename':file,'md5':hashlib.md5(open('.\\email_phishing_detector\\src\\email_phishing_detector\\attachments\\' + file,'rb').read()).hexdigest()})

        return hashes

    def virus_total(self,links):
        with virustotal_python.Virustotal(self.key) as vtotal:
            print('##########################################################')
            print('VIRUS TOTAL REPORT')
            print('##########################################################')
            print('')
            print('----------------------------------------------------------')
            print('URLs in Email Body')
            for link in links:
                try:
                    print('----------------------------------------------------------')
                    url_id = urlsafe_b64encode(link.encode()).decode().strip("=")
                    resp = vtotal.request(f"urls/" + url_id)
                    print(f"URL: {link}")
                    print(f"Link: {resp.data['links']}")
                    print()
                    for x in resp.data['attributes']['last_analysis_results']:
                        print(f"Engine: {x}, Category: {resp.data['attributes']['last_analysis_results'][x]['category']}, Result: {resp.data['attributes']['last_analysis_results'][x]['result']}")
                    
                                        


                except virustotal_python.VirustotalError as err:
                    print(f"Failed to send URL: {link} for analysis and get the report: {err}")
                    continue

                print('----------------------------------------------------------')
                print('')
                print('')


            hashes = self.get_hash()
            print('----------------------------------------------------------')
            print('EMAIL ATTACHMENTS')
            with virustotal_python.Virustotal(self.key) as vtotal:
                for hash in hashes:
                    try:
                        print('----------------------------------------------------------')
                        resp = vtotal.request(f"files/{hash['md5']}")

                        print(f"Filename: {hash['filename']}")
                        print(f"Md5: {hash['md5']}")
                        print(f"Type: {resp.data['attributes']['type_description']}")
                        print(f"Link: {resp.data['links']}")
                        print()
                        for x in resp.data['attributes']['sandbox_verdicts']:
                            print(f"Sandbox: {resp.data['attributes']['sandbox_verdicts'][x]['sandbox_name']}, Category: {resp.data['attributes']['sandbox_verdicts'][x]['category']}, Classification: {resp.data['attributes']['sandbox_verdicts'][x]['malware_classification']}")
                    except virustotal_python.VirustotalError as err:
                        print(f"Failed to send file: {hash['filename']} for analysis and get the report: {err}")
                        continue

                print('----------------------------------------------------------')
                print('')
                print('')



    def email_scan(self):

        # get email body
        with open(self.file, 'rb') as fp:  # select a specific email file from the list
            #name = fp.name # Get file name
            msg = BytesParser(policy=policy.default).parse(fp)
        text = msg.get_body(preferencelist=('plain')).get_content()
        urls = re.findall('(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-&?=%.]+', text)
        fp.close()

        # get attachments

        for root, dirs, files in os.walk('.\\email_phishing_detector\\src\\email_phishing_detector\\attachments'):
            for file in files:
                if file == 'README':
                    continue
                os.remove(os.path.join(root,file))
        msg = email.message_from_file(open(self.file))
        attachments=msg.get_payload()
        for attachment in attachments:
            try:
                fnam=attachment.get_filename()
                if not fnam:
                    continue
                f=open('.\\email_phishing_detector\\src\\email_phishing_detector\\attachments\\' + fnam, 'wb').write(attachment.get_payload(decode=True,))
            except Exception as e:
                print(e)
                pass

        return urls

    def run(self):
        links = self.email_scan()
        expanded_links = self.expand_links(links)
        self.virus_total(expanded_links)
        
