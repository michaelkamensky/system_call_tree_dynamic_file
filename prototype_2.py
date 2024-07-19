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
        if not self.is_empty():
            return self.items.pop(0)
        else:
            raise IndexError("Dequeue from an empty queue")

class Stack:
    def __init__(self):
        self.items = []

    def is_empty(self):
        return len(self.items) == 0

    def push(self, item):
        self.items.append(item)

    def pop(self):
        if not self.is_empty():
            return self.items.pop()
        else:
            raise IndexError("Pop from an empty stack")

class SystemCall:
    def __init__(self, line, type_num, pid, ppid):
        self.message = line
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
    
    def get_clone_id(self):
        if self.are_we_clone():
            return int(self.message.attributes['exit'][0])

    def get_message(self):
        return self.message
    
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
    
    def get_pid(self):
        return self.pid

    def add_child(self, child):
        self.children.append(child)
    
    def set_parent(self, parent):
        self.parent = parent

    def get_syscalls(self):
        return self.syscall
    
    def get_children(self):
        return self.children
    
    def __str__(self):
        return str(self.pid)
    
        

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

def breath_first_search(root):
        
    queue = Queue()
    queue.enqueue(root)
    result = []
    num=0

    while not queue.is_empty():
        process = queue.dequeue()
        num += 1
        for syscall in process.get_syscalls():
            #result.append(convert_message(syscall.get_message()))
            print('<'+ str(num) + '>' + convert_message(syscall.get_message()))

        #for child in process.get_children():
            #queue.enqueue(child)
        
    #return result

def depth_first_search(root):
    stack = Stack()
    stack.push(root)
    result = []
        
    while not stack.is_empty():
        process = stack.pop()
        #result.append(node.value)
        # Add children to stack in reverse order to maintain correct order in DFS
        for child in reversed(node.children):
            stack.push(child)
        
    return result

def print_out_trees(root, dict):
    for r in root:
        my_process = dict[r]
        #print(my_process)
        print('\n the parent is = ' + str(my_process))
        print(breath_first_search(my_process))

def create_file(a):
    process_dict = {}
    roots = []
    bfot = []
    num_proccess = 0

    # now using this structure and a tree we will parse the audit log while also using a tree
    for m in a.messages:
        message = a.messages[m]
        #my_node = TreeNode(message.id)
        #print("new message here \n\n\n")
        for line in message.lines:
            #print(line)
            if line.type == "SYSCALL": # or line.type == "EXECVE":
                #tree.add_node(line.id, line.attributes['ppid'])
                my_syscall = SystemCall(line, line.attributes['syscall'][0], line.attributes['pid'][0],
                                        line.attributes['ppid'][0])
                if my_syscall.are_we_clone():
                    #print('process correctly made')
                    # if there is a clone a new process is created now we handle its logic
                    # if there is a clone a new process MUST Be created
                    my_process = Process(my_syscall.get_clone_id())
                    num_proccess += 1
                    # adding the process to the dict
                    process_dict[my_process.get_pid()] = my_process
                    # now to the process has been added to the dicts
                    # take care of any parental relationships
                    if my_syscall.get_pid() in process_dict:
                        parent_process = process_dict[my_syscall.get_pid()]
                        # now establish the relationships
                        parent_process.add_child(my_process)
                        parent_process.add_syscall(my_syscall)
                        my_process.set_parent(parent_process)
                else:
                    #this is not a clone system call but we still need to add it to the right process
                    # there is a case for bfot where audit is not aware of a process
                    if my_syscall.get_pid() not in process_dict:
                        # there has yet to be a clone this is a root process
                        #print('this ran')
                        root_process = Process(my_syscall.get_pid())
                        num_proccess += 1
                        process_dict[root_process.get_pid()] = root_process
                        root_process.set_parent(my_syscall.get_ppid())
                        root_process.add_syscall(my_syscall)
                        roots.append(root_process)
                        bfot.append(my_syscall.get_ppid())
                    else:
                        # the process does exist we need to add the syscall to it
                        my_process = process_dict[my_syscall.get_pid()]
                        my_process.add_syscall(my_syscall)
    print(len(bfot))
    print(num_proccess)
    #print_out_trees(roots, process_dict)

    
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
    create_file(a)



main()
