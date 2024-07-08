import os # needed for the terminal commands
import argparse 
import re # needed parsing using regular expressions
import subprocess # needed for reading the terminal so we can stop the process

# creating a tree data structure to keep track of the information that is being pasrsed

class TreeNode:
    def __init__(self, node_id, parent_id=None):
        self.node_id = node_id
        self.parent_id = parent_id
        self.children = []

    def add_child(self, child_node):
        self.children.append(child_node)

class Tree:
    def __init__(self):
        self.nodes = {}
        self.root = None

    def add_node(self, node_id, parent_id):
        new_node = TreeNode(node_id, parent_id)
        self.nodes[node_id] = new_node
        
        if parent_id is None:
            self.root = new_node
        elif parent_id in self.nodes:
            self.nodes[parent_id].add_child(new_node)
        else:
            raise ValueError(f"Parent with ID {parent_id} not found")

        # Ensure the root is set correctly
        self.set_root()

    def set_root(self):
        for node in self.nodes.values():
            if node.parent_id is None:
                self.root = node
                break

    def _find(self, node, node_id):
        if node.node_id == node_id:
            return node
        for child in node.children:
            result = self._find(child, node_id)
            if result:
                return result
        return None

    def traverse(self):
        if not hasattr(self, 'root'):
            return []
        return self._traverse(self.root, [])

    def _traverse(self, node, traversal):
        traversal.append(node.node_id)
        for child in node.children:
            self._traverse(child, traversal)
        return traversal

    def traverse_with_parent_id(self):
        if not hasattr(self, 'root'):
            return []
        return self._traverse_with_parent_id(self.root, [])

    def _traverse_with_parent_id(self, node, traversal):
        traversal.append((node.node_id, node.parent_id))
        for child in node.children:
            self._traverse_with_parent_id(child, traversal)
        return traversal

    def add_node_from_line(self, line):
        match = re.search(r"ppid=(\d+)", line)
        if match:
            parent_id = int(match.group(1))
        else:
            parent_id = None

        match = re.search(r"pid=(\d+)", line)
        if match:
            node_id = int(match.group(1))
        else:
            raise ValueError("No pid found in line")

        self.add_node(node_id, parent_id)

# my custom function that will parse the dynamic file and find instances of where 
# there is a process start is and writes all those instances in to another file
# Function to parse the file and find lines with "type=SERVICE_START"
def parse_file(input_filename, output_filename):
    # creating a list to hold the parent id so I can keep track of whose parent is who's
    parent_id = []
    # creating a basic tree that will keep track of children
    tree = Tree()
    level = 0
    with open(input_filename, 'r') as infile, open(output_filename, 'w') as outfile:
        for line in infile:
            #if "clone" or "execve" in line:
            if "clone" in line:
                # this is a clone line we got to add a ppid if it isn't in the list
                tree.add_node_from_line(line)
                outfile.write(line)
    print(tree.traverse_with_parent_id())           




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
    parse_file(args.audit, args.out)

    a = AuditLog(args.audit)
    m100 = a.messages[100] # AuditLogMessage
    print(m100.id)
    for p in m100.lines: # AuditLogLine
        print(p.type)
        print(p.attributes)
        if p.type == "EXECVE":
            if "argc" in p.attributes:
                print(p.attributes["argc"])

main()

