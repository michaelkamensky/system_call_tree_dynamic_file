import os # needed for the terminal commands
import argparse 
import re # needed parsing using regular expressions
import subprocess # needed for reading the terminal so we can stop the process

# creating a data structure to keep track of the information that is being pasrsed
class AuditLog():

    def __init__(self, file):
        self.audit_id = []
        #lets parse the file based on the audit ID
        with open(file, 'r') as infile:
            for line in file:
                match = re.search(r"msg=audit(\d)", line)
                if match:
                    if match not in self.audit_id:
                        self.audit_id.append(match)

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
    a.print_ids()


main()
