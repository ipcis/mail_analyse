from flask import Flask, request, render_template
from extract_msg import Message
import hashlib
import sys


import yara


import re, io, os, uuid
from fnmatch import fnmatch
import magic # python-magic-bin==0.4.14






"""

Gewuenschte Funktionen:

- Screenshots
- Dateianhenge sicher oeffnen und den Output als Screenshot
- Links verfolgen und auswerten
- Scoring System
- PDF to Image: https://www.geeksforgeeks.org/convert-pdf-to-image-using-python/
- ZIP entpacken? ISO, 7z? DOC, DOCx, DOCM, 
- MD5 check
- IoC check
- Strings ueber Anhaenge

"""





# Verzeichnis mit den YARA-Regeln
rules_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")

# Kompilieren der Regeln aus dem Verzeichnis
rules = {}
for rule_file in os.listdir(rules_directory):
    if rule_file.endswith('.yar'):
        rule_name = os.path.splitext(rule_file)[0]
        rule_path = os.path.join(rules_directory, rule_file)
        rules[rule_name] = rule_path
compiled_rules = yara.compile(filepaths=rules)









#create a uniq id
#uid = str(uuid.uuid4())

# Get the directory of the current Python script
script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))





app = Flask(__name__)






def search_urls(s):
    # search text input and extract urls
    print("")
    print("[+] searching for URLs...")
    match = re.findall(r'(https?://\S+)', s)

    return match


def search_uncs(s):
    # search text input and extract uncs
    print("")
    print("[+] searching for UNCs...")
    match = re.findall(r'\\\\([a-z0-9_.$●-]+)\\([a-z0-9_.$●-]+)', s)

    return match


def search_emails(s):
    # search text input and extract emails
    print("")
    print("[+] searching for e-mail addresses in header...")
    match = re.findall(r'[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+', s)

    return match


def search_ips(s):
    # search text input and extract emails
    print("")
    print("[+] searching for ip addresses...")
    #match = re.findall(r'[0-9]+(?:\.[0-9]+){3}', s)
    match = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s)

    return match


def extract_header(msg):
    header = ""
    for k, v in msg.header.items():
        header = header + k + v
    return header

"""def extract_msg_data(msg):


     msg_sender = msg.sender
    msg_date = msg.date
    msg_subj = msg.subject
    msg_message = msg.body


    #print("SENDER:" + msg_sender)
    #print("DATE:" + msg_date)
    #print("SUBJECT:" + msg_subj)
    #print("MESSAGE:" + msg_message)



    print()
    print("-------------- INFO -----------------")

    print('Sender: {}'.format(msg_sender))
    print('Sent On: {}'.format(msg_date))
    print('Subject: {}'.format(msg_subj))

    print("--------------------------------------")
    print()

    print()
    print("-------------- HEADER -----------------")

    for k, v in msg.header.items():
        print("{}: {}".format(k, v))

    print("--------------------------------------")
    print()


    print()
    print("-------------- BODY -----------------")
    print(msg.body)
    print("-------------------------------------")
    print() """


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def extract_attachments(msg, out_dir):
    print("[+] extract attachments...")

    msg.save(customPath=out_dir, attachmentsOnly=False, extractEmbedded=False, skipEmbedded=True, skipHidden=True, useFileName=True)

    root = out_dir
    pattern = "*.*"

    data_out = []

    for path, subdirs, files in os.walk(root):
        for name in files:
            if fnmatch(name, pattern):
                print(os.path.join(path, name))
                print("")
                print("FILENAME:", name, " FILETYPE:", magic.from_file(os.path.join(path, name)), " MD5:", md5(os.path.join(path, name)))

                file = os.path.join(path, name)
                matches = compiled_rules.match(file)
                if matches:
                    for match in matches:
                        print(f"Suspicious file found: {name} (matched rule: {match.rule})")
                        yara_data = (f"Suspicious file found: {name} (matched rule: {match.rule})")
                        data_out.append(yara_data)


                data = "FILENAME:", name, " FILETYPE:", magic.from_file(os.path.join(path, name)), " MD5:", md5(os.path.join(path, name))
                data_out.append(data)
    return data_out



@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload():
    uid = str(uuid.uuid4())
    analyse_out_dir = script_dir + "\\" + uid
    msg_file = request.files['msg']

    try:
        msg = Message(msg_file)
    except:
        print('Error')
        return "Error"

    #extract_msg_data(msg)
    """     print("")
    print(f'From: {msg.sender}')
    print(f'To: {msg.to}')
    print(f'Subject: {msg.subject}')
    print("") """
    #print(f'Date: {msg.get_message_delivery_time()}') # Datum und Uhrzeit der Nachricht


    attachments_out = extract_attachments(msg, analyse_out_dir)




    msgbodyurls = search_urls(msg.body)
    msgbodyuncs = search_uncs(msg.body)
    msgbodyips = search_ips(msg.body)

    msgheaderemails = search_emails(extract_header(msg))
    msgheaderips = search_ips(extract_header(msg))

    msgheader = extract_header(msg)

    #return 'File uploaded successfully.'
    return render_template('result.html', sender=msg.sender, to=msg.to, subject=msg.subject, msguid=uid, header=msgheader, body=msg.body, attachments=attachments_out, urls=msgbodyurls, uncs=msgbodyuncs, ips=msgbodyips, emailsh=msgheaderemails, ipsh=msgheaderips)


if __name__ == '__main__':
    app.run()
