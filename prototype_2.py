import os # needed for the terminal commands
import argparse 
import re # needed parsing using regular expressions
import subprocess # needed for reading the terminal so we can stop the process
from collections import defaultdict
import copy

class Queue:
    def __init__(self):
        self.items = []

    def is_empty(self):
        return len(self.items) == 0

    def enqueue(self, item):
        self.items.append(item)

    def dequeue(self):
        if self.is_empty():
            raise IndexError("Dequeue from an empty queue")
        return self.items.pop(0)

    def peek(self):
        if self.is_empty():
            raise IndexError("Peek from an empty queue")
        return self.items[0]

    def size(self):
        return len(self.items)


class SystemCall:
    def __init__(self, message, type_num, pid, ppid):
        self.message = message
        self.pid = int(pid)
        self.ppid = int(ppid)
        self.syscall_num= int(type_num)
        
    def get_pid(self):
        return self.pid
    
    def get_ppid(self):
        return self.ppid
    
    def get_syscall_num(self):
        return self.syscall_num
    
    def are_we_clone(self):
        if self.syscall_num == 56:
            return True
        else:
            return False
    
    def __str__(self):
        return str(self.message)


class Process:

    def __init__(self, pid):
        self.parent = None
        self.pid = pid
        self.syscall = []
        self.children = []

    def add_syscall(self, syscall):
        self.syscall.append(syscall)

    def add_child(self, child):
        self.children.append(child)
    
    def set_parent(self, parent):
        self.parent = parent

    def get_syscalls(self):
        return self.syscall
    
    def get_children(self):
        return self.children
    
        

# now we need a lines class to keep track of each line there meta deta

class line():
    def __init__(self, id ,my_line):
        self.id = id
        self.type = "None"
        self.age = ""
        self.line = my_line
        self.attributes = defaultdict(list)
        self.parse_string_to_dict(my_line)
    
    def __str__(self):
        return self.line
    
    def are_we_clone(self):
        if len(self.attributes['syscall']) > 0:
            if self.attributes['syscall'][0] == '56':
                return True
        else:
            return False
    
    def parse_string_to_dict(self, input_string):
        match = re.search(r"msg=audit\((\d+\.\d+):(\d+)\):", input_string)
        if match:
            self.age = str(match.group(0) + "." + match.group(1) + ":" + match.group(2)) 
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
    
    def __str__(self):
        return_string = ''
        for l in self.lines:
            return_string += str(l)
        return return_string
    
    
        
class AuditLog():

    def __init__(self, file):
        self.audit_id = {}
        self.messages = {}
        # self.attributes = {}
        #lets parse the file based on the audit ID
        with open(file, 'r') as infile:
            for line in infile:
                match = re.search(r'msg=audit\(([^)]+)\)', line)
                if match:
                    if str(match.group(0)) not in self.audit_id:
                        num = len(self.audit_id)
                        self.audit_id[match.group(0)] = num
                        m = message(num, match.group(0))
                        m.add_line(line)
                        self.messages[num] = m
                    else: 
                        num = self.audit_id[match.group(0)]
                        num = self.messages[num]
                        num.add_line(line)

    def print_ids(self):
        for id in self.audit_id:
            print(id)

# converts a message into a printable form
def convert_message(message):
    return_string = ""
    for line in message.lines:
        #print(type(line))
        if line.are_we_clone():
            #print(line.attributes['pid'])
            return_string += "pid = " + line.attributes['pid'][0] + ": CLONE at " + line.id
    if len(return_string) > 0:
        return return_string


def depth_first_search(root, dict):
    for r in root:
        my_process = dict[r]
        for syscall in my_process.get_syscalls():
            #print(syscall)
            print(convert_message(syscall.message))

    
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
    #print(args.audit)
    #print(args.out)
    a = AuditLog(args.audit)
    #tree = Tree()
    process_dict = {}
    roots = []
    bfot = []

    # now using this structure and a tree we will parse the audit log while also using a tree
    for m in a.messages:
        message = a.messages[m]
        #my_node = TreeNode(message.id)
        #print("new message here \n\n\n")
        for line in message.lines:
            #print(line)
            if line.type == "SYSCALL": # or line.type == "EXECVE":
                #tree.add_node(line.id, line.attributes['ppid'])
                my_syscall = SystemCall(message, line.attributes['syscall'][0], line.attributes['pid'][0],
                                        line.attributes['ppid'][0])
                if my_syscall.are_we_clone():
                    # first we take care of the system call
                    #print("my_syscall.get_pid() = " + str(my_syscall.get_pid()) + " my_syscall.get_ppid() ="+ str(my_syscall.get_ppid())  )
                    if my_syscall.get_pid() not in process_dict:
                        process = Process(my_syscall.get_pid())
                        process.add_syscall(my_syscall)
                        process_dict[my_syscall.get_pid()] = process
                        # remove from boft since now the possible parent exists
                    else:
                        process = process_dict[my_syscall.get_pid()]
                        process.add_syscall(my_syscall)
                    # now we take care of the parent
                    if my_syscall.get_ppid() in process_dict:
                        if my_syscall.get_pid() in bfot:
                            bfot.remove(my_syscall.get_pid())
                        parent_process = process_dict[my_syscall.get_ppid()]
                        parent_process.add_child(process)
                        process.set_parent(parent_process)
                    else:
                        # there is a possible before our time here we got to acoount for that
                        if my_syscall.get_ppid() not in process_dict and my_syscall.get_ppid() not in bfot:
                            bfot.append(my_syscall.get_ppid())
                            roots.append(my_syscall.get_pid())
    depth_first_search(roots, process_dict)



                





main()
