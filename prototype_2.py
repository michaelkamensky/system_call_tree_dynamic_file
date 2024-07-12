import os # needed for the terminal commands
import argparse 
import re # needed parsing using regular expressions
import subprocess # needed for reading the terminal so we can stop the process
from collections import defaultdict

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


class TreeNode:
    def __init__(self, node_id):
        self.id = node_id
        self.parent = None
        self.children = []
        

    def add_child(self, child_node):
        self.children.append(child_node)
        child_node.parent = self
    
    def set_parent(self, parent_id):
        self.parent = parent_id
    
    def __str__(self):
        return str(self.id[0])



class Tree:
    def __init__(self):
        self.nodes = {}
        self.root = None

    def add_node(self, node_id, parent_id):
        if node_id not in self.nodes:
            node = TreeNode(node_id)
            self.nodes[node_id] = node
            #print(parent_id)
            if len(parent_id) > 0:
                if parent_id[0] not in self.nodes:
                    parent_node = TreeNode(parent_id[0])
                    parent_node.add_child(node)
                    self.nodes[parent_id[0]] = parent_node
                    node.set_parent(parent_id[0])
                else:
                    node.set_parent(parent_id[0])
                    parent_node = self.nodes[parent_id[0]]
                    parent_node.add_child(node)
            else:
                self.root = node 


    def update_root(self):
        for n in self.nodes:
            node = self.nodes[n]
            if node.parent == None:
                self.root = node
                break


    def breath_first_search(self, node):
        if not self.root:
            return []

        queue = Queue()
        queue.enqueue(self.root)
        visited = []

        while not queue.is_empty():
            current_node = queue.dequeue()
            visited.append(current_node.id)

            for child in current_node.children:
                queue.enqueue(child)

        return visited
        



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
    
    
        
class AuditLog():

    def __init__(self, file):
        self.audit_id = {}
        self.messages = {}
        # self.attributes = {}
        #lets parse the file based on the audit ID
        with open(file, 'r') as infile:
            for line in infile:
                match = re.search(r"pid=(\d+)", line)
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
    #print(args.audit)
    #print(args.out)
    a = AuditLog(args.audit)
    tree = Tree()

    # now using this structure and a tree we will parse the audit log while also using a tree
    for m in a.messages:
        message = a.messages[m]
        #my_node = TreeNode(message.id)
        #print("new message here \n\n\n")
        for line in message.lines:
            if line.type == "SYSCALL" or line.type == "EXECVE":
                tree.add_node(line.id, line.attributes['ppid'])
    tree.update_root()
    print(tree.root)
    print(tree.root.children)
    #print(tree.breath_first_search(tree.root))

                





main()
