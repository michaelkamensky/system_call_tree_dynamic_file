import os # needed for the terminal commands
import argparse 
import re # needed parsing using regular expressions
import subprocess # needed for reading the terminal so we can stop the process
from collections import defaultdict

class TreeNode:
    def __init__(self, node_id, time):
        self.id = node_id
        self.time = time
        self.children = []

    def add_child(self, child_node):
        self.children.append(child_node)
        child_node.parent = self



class Tree:
    def __init__(self):
        self.nodes = {}
        self.root = None

    def add_node(self, node_id, parent_id, time):
        new_node = TreeNode(node_id, time)
        if node_id not in self.nodes:
            self.nodes[node_id] = new_node
        else:
            node_in_question = self.nodes[node_id]
            if node_in_question.time > time or node_in_question.time == None:
                node_in_question.time = time
                new_node = node_in_question
        if len(parent_id) > 0:
            if parent_id[0] not in self.nodes:
                parent_node_new =  TreeNode(parent_id, None)
                self.nodes[parent_id[0]] = parent_node_new
            parent_node = self.nodes[parent_id[0]]
            parent_node.add_child(new_node)


    def update_root(self):
        # Find the node that doesn't have a parent, this node is the root
        for node in self.nodes.values():
            if node.parent is None:
                self.root = node
                break

        



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
                tree.add_node(line.id, line.attributes['ppid'], line.age)
        tree.update_root()

                





main()
