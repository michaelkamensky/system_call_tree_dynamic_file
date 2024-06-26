import os

os.system('sudo auditd start')
os.system('sudo auditctl -r 1000')
os.system('sudo auditctl -s')
os.system('sudo aureport --syscall')
#os.system('auditd status')