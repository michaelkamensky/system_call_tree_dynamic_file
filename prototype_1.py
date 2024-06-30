import os # needed for the terminal commands
import subprocess # needed for reading the terminal so we can stop the process

# my custom function that will parse the dynamic file and find instances of where 
# there is a process start is and writes all those instances in to another file
# Function to parse the file and find lines with "type=SERVICE_START"
def parse_file(input_filename, output_filename):
    with open(input_filename, 'r') as infile, open(output_filename, 'w') as outfile:
        for line in infile:
            if "type=SERVICE_START" in line:
                outfile.write(line)




os.system('sudo auditd start')
os.system('sudo auditctl -r 1000')
os.system('touch tree_audit_process.txt')
#os.system('sudo auditctl -a always -S fork')
os.system('sudo less /var/log/audit/audit.log > dynamic_autilog.txt')
parse_file('dynamic_autilog.txt', 'tree_audit_process.txt')
#while (input() != "^C"):
    # we need some code to help break out of this loop

    
#os.system('sudo aureport --syscall')
#os.system('auditd status')