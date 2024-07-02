import os # needed for the terminal commands
import re # needed parsing using regular expressions
import subprocess # needed for reading the terminal so we can stop the process

# creating a tree data structure to keep track of the information that is being pasrsed

class TreeNode:
    def __init__(self, key, pid=None):
        self.key = key
        self.pid = pid
        self.children = []

    def add_child(self, child_node):
        self.children.append(child_node)

class Tree:
    def __init__(self, root=None):
        self.root = root

    def add_child(self, parent_key, child_key):
        parent_node = self._find(self.root, parent_key)
        if parent_node:
            child_node = TreeNode(child_key, parent_node.key)
            parent_node.add_child(child_node)

    def _find(self, node, key):
        if node is None:
            return None
        if node.key == key:
            return node
        for child in node.children:
            result = self._find(child, key)
            if result:
                return result
        return None

    def traverse(self):
        if not self.root:
            return []
        return self._traverse(self.root, [])

    def _traverse(self, node, traversal):
        traversal.append(node.key)
        for child in node.children:
            self._traverse(child, traversal)
        return traversal

    def traverse_with_pid(self):
        if not self.root:
            return []
        return self._traverse_with_pid(self.root, [])

    def _traverse_with_pid(self, node, traversal):
        traversal.append((node.key, node.pid))
        for child in node.children:
            self._traverse_with_pid(child, traversal)
        return traversal

# my custom function that will parse the dynamic file and find instances of where 
# there is a process start is and writes all those instances in to another file
# Function to parse the file and find lines with "type=SERVICE_START"
def parse_file(input_filename, output_filename):
    # creating a list to hold the parent id so I can keep track of whose parent is who's
    parent_id = []
    # basic integer var that keeps track of level of process
    level = 0
    with open(input_filename, 'r') as infile, open(output_filename, 'w') as outfile:
        for line in infile:
            if "clone" or "execve" in line:
                # this is a clone line we got to add a ppid if it isn't in the list
                match = re.search("ppid=(\d+)", line)
                if match:
                    ppid = int(match.group(1))
                    # if ppid is new add it to the list
                    if ppid not in parent_id:
                        parent_id.append(ppid)
                        #outfile.write(str(ppid) + "\n")
                
                    #outfile.write(line)




#os.system('sudo auditd start')
#os.system('sudo auditctl -r 1000')
os.system('touch tree_audit_process.txt')
#os.system('sudo auditctl -S fork')
#os.system('sudo auditctl -a always,exit -F arch=b64 -S clone -k clone_syscall')
os.system('sudo less /var/log/audit/audit.log > dynamic_autilog.txt')
parse_file('dynamic_autilog.txt', 'tree_audit_process.txt')
#while (input() != "^C"):
    # we need some code to help break out of this loop

    
#os.system('sudo aureport --syscall')
#os.system('auditd status')