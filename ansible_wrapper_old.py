from ansible.playbook import PlayBook
import ansible.playbook
import ansible.inventory
from ansible import callbacks
from ansible import utils
import json
import random
import string
import os

def create_playbook(text):
    """
    Dynamically creates a playbook file out of
    text. Returns the path to the
    playbook file
    """
    def playbook_name():
        """
        Generates a name for playbook consisting of
        the format playbook_X.yaml, where X is string of
        random ascii letters of length 5
        """
        rand_id = ''.join(random.choice(string.ascii_letters) for _ in range(5))
        return 'playbook_{}.yaml'.format(rand_id)

    playbook_path = "{}/{}".format(os.getcwd(), playbook_name())
    with open(playbook_path, 'w') as out_file:
        out_file.write(text)

    return playbook_path

def create_inventory(text):
    """
    Dynamically creates an inventory file from
    the constiuent text
    """
    inventory_path = "{}/hosts".format(os.getcwd())
    with open(inventory_path, 'w') as out_file:
        out_file.write(text)

    return inventory_path

def remove_file(path):
    """Remove the temporary file
    """
    os.remove(path)

def remove_playbook(path):
    #DEPRECATED: For backwar compatibitily only
    remove_file(path)

def create_and_play(playbook_text, hosts):
    """
    Utility method that creates and runs
    a playbook
    """
    playbook_file = create_playbook(playbook_text)
    results = playbook(playbook_file, hosts)
    remove_file(playbook_file)
    return results

def playbook(playbook, hosts):
    """
    Wrapper to playbook API
    Parameters:
        playbook- (str) path to playbook
        hosts- list of hosts, or path to a hosts file
    """
    inventory = ansible.inventory.Inventory(hosts)

    #create these objects- required by playbook
    stats = callbacks.AggregateStats()
    playbook_cb = callbacks.PlaybookCallbacks(verbose=utils.VERBOSITY)
    runner_cb = callbacks.PlaybookRunnerCallbacks(stats, verbose=utils.VERBOSITY)

    pb = PlayBook(playbook=playbook,
                    inventory=inventory,
                    stats = stats,
                    callbacks = playbook_cb,
                    runner_callbacks = runner_cb,
                    #check=True, #sandboxes execution
                    forks=10)
    #results is a dict
    results = pb.run()
    return results

def print_results(pr):
    print json.dumps(pr, sort_keys=True, indent=4, separators=(',', ': '))

if __name__ == "__main__":
    hosts = ["10.12.0.14"]
    playbook('./setup_ovs.yaml', hosts)
    print json.dumps(pr, sort_keys=True, indent=4, separators=(',', ': '))

