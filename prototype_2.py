import os # needed for the terminal commands
import argparse 
import re # needed parsing using regular expressions
import subprocess # needed for reading the terminal so we can stop the process
from collections import defaultdict

# now we need a lines class to keep track of each line there meta deta

class line():
    def __init__(self, id ,line):
        self.id = id
        self.type = "none"
        self.line = line
        self.attributes = defaultdict(list)
        self.parse_string_to_dict(line)
    
    def __str__(self):
        return self.line
    
    def parse_string_to_dict(self, input_string):
        # Regular expression to find key-value pairs
        pattern = r'(\w+)\s*=\s*(\w+)'

        # Find all matches of the pattern in the input string
        matches = re.findall(pattern, input_string)
        
        # Iterate over the matches and populate the dictionary
        for key, value in matches:
            # need to catch the type stringand put it in a sperate category if type
            if key == "type":
                self.type = value
            else:
                self.attributes[key].append(value)

# creating a data structure to keep track of the information that is being pasrsed
class message():

    def __init__(self, num, id):
        self.id = id
        self.num = num
        self.lines = []
    
    def add_line(self, my_line):
        self.lines.append(line(self.id, my_line))

    def get_id(self):
        return id
    
    
        
class AuditLog():

    def __init__(self, file):
        self.audit_id = {}
        self.messages = {}
        # self.attributes = {}
        #lets parse the file based on the audit ID
        with open(file, 'r') as infile:
            for line in infile:
                match = re.search(r"msg=audit\((\d+\.\d+):(\d+)\):", line)
                if match:
                    if str(match.group(1)) not in self.audit_id:
                        num = len(self.audit_id)
                        self.audit_id[match.group(1)] = num
                        m = message(num, match.group(1))
                        m.add_line(line)
                        self.messages[num] = m
                    else: 
                        num = self.audit_id[match.group(1)]
                        num = self.messages[num]
                        num.add_line(line)

    def print_ids(self):
        for id in self.audit_id:
            print(id)
    
    

#os.system('sudo auditd start')
#os.system('sudo auditctl -r 1000')
#os.system('touch tree_audit_process.txt')
#os.system('sudo auditctl -S fork')
#os.system('sudo auditctl -a always,exit -F arch=b64 -S clone -k clone_syscall')
#os.system('sudo less /var/log/audit/audit.log > dynamic_autilog.txt'

#parse_file('dynamic_autilog.txt', 'tree_audit_process.txt')
#while (input() != "^C"):
    # we need some code to help break out of this loop

    
#os.system('sudo aureport --syscall')
#os.system('auditd status')
def main():
    parser = argparse.ArgumentParser(
                        prog='prtotype_1',
                        description='Create process tree report from given audit log')
    
    parser.add_argument('-a', '--audit', dest='audit', required=True, metavar='FILE')          # positional argument
    parser.add_argument('-o', '--outfile', dest='out', required=True, metavar='FILE')
    #parser.add_argument('filename')           # positional argument
    args = parser.parse_args()
    print(args.audit)
    print(args.out)
    a = AuditLog(args.audit)
    #for m in a.messages:
        #message = a.messages[m]
        #print("new message \n\n\n")
        #for l in message.lines:
            #print(l)
    m100 = a.messages[100] # AuditLogMessage
    print(m100.id)
    for p in m100.lines: # AuditLogLine
        print(p.type)
        print(p.attributes)
        if p.type == "EXECVE":
            if "argc" in p.attributes:
                print(p.attributes["argc"])



main()
