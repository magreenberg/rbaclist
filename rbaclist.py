import argparse
import json
import sys
import subprocess
from types import NoneType

class RBACObject(dict):
    def __init__(self, obj):
        super(RBACObject, self).__init__()
        self.obj = obj

    def __len__(self):
        return len(self.obj)

    def get(self, search_key):
        ret = ""
        for key, value in self.obj.iteritems():
            if search_key == key:
                ret = value
                break
        return ret

    def get_metadata_name(self):
        metadata = self.get_metadata()
        name = metadata.get('name')
        return name

    def get_metadata_namespace(self):
        metadata = self.get_metadata()
        name = metadata.get('namespace')
        return name

    def get_metadata(self):
        return self.obj.get('metadata')

    def get_kind(self):
        return self.get('kind')

class RBACObjects(object):
    def __init__(self):
        self.all = []

    def load_objs(self, kind, class_type):
        # oc get kind --all-namespaces -o json
        cmd = ['oc', 'get', kind, '--chunk-size=0', '--all-namespaces', '-o', 'json']
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except:
            print 'Failed to run the \"oc\" command. Ensure that the \"oc\" command is in the PATH.'
            print " ".join(cmd)
            sys.exit(1)
        out, err = proc.communicate()
        if err:
            print "Failed to load data from OpenShift: ", err
            print "ensure that the \"oc\" logged in user is: system:admin"
            sys.exit(1)
        alldata = json.loads(out)
        if not isinstance(alldata, dict):
            print "Invalid JSON format. Expected \"dict\""
            sys.exit(1)
        for obj in alldata['items']:
            self.all.append(class_type(obj))

  # DEBUG ONLY
#   def loadDataFromFile(self):
#       filename = 'data/' + self.kind.lower + '/json'
#       try:
#           with open(filename, 'r') as fp:
#               alldata = json.load(fp)
#       except:
#           print "error loading JSON file: " + filename
#
#       fp.close()
#       #print alldata
#       #print type(alldata)
#       if not isinstance(alldata, dict):
#           print "Invalid JSON format. Expected \"dict\""
#           sys.exit(1)
#       return alldata

    def get_all_items(self):
        return self.get_all()

    def get_all(self):
        return self.all

    def get_obj_with_metadata_name(self, name):
        for obj in self.get_all():
            if obj.get_metadata_name() == name:
                return obj
        return None
    
class Output(object):

    def __init__(self):
        self.out_lines = []

    def add_line(self, line):
        self.out_lines.append(line)

    def print_sorted(self):
        output = sorted(self.out_lines)
        for line in output:
            print line

    def print_sorted_unique(self):
        output = sorted(set(self.out_lines))
        for line in output:
            print line

    def get_num_lines(self):
        return len(self.out_lines)

    
# Bindings
# ========
class Binding(RBACObject):
    def __init__(self, obj):
        super(Binding, self).__init__(obj)

    def get_subjects(self):
        return self.get('subjects')

    def get_roleref(self):
        return self.get('roleRef')

    def get_roleref_kind(self):
        role_ref = self.get_roleref()
        return role_ref.get('kind')

    def get_roleref_name(self):
        role_ref = self.get_roleref()
        return role_ref.get('name')

    def to_output(self, additional_text):
        print '----------'
        print self.get_kind() + ' name=' + self.get_metadata_name() + ' namespace=' + \
            self.get_metadata_namespace() + ' roleRef.kind=' + self.get_roleref_kind() + \
            ' roleRef.name=' + self.get_roleref_name() + ' ' + additional_text

class RoleBinding(Binding):
    pass

class ClusterRoleBinding(Binding):
    pass

class ClusterRoleBindings(RBACObjects):
    def __init__(self):
        super(ClusterRoleBindings, self).__init__()
        self.objs = self.load_objs('ClusterRoleBinding', ClusterRoleBinding)

class RoleBindings(RBACObjects):
    def __init__(self):
        super(RoleBindings, self).__init__()
        self.objs = self.load_objs('RoleBinding', RoleBinding)


# Roles
# =====
class Role(RBACObject):

    def __init__(self, obj):
        super(Role, self).__init__(obj)

    def get_rules(self):
        return self.get('rules')

    def to_output(self, overriding_namespace):
        if overriding_namespace != self.get_metadata_namespace():
            msg = ' OverridingNamespace=' + overriding_namespace
        else:
            msg = ""
        print self.get_kind() + ' name=' + self.get_metadata_name() + ' namespace=' + self.get_metadata_namespace() + msg

class ClusterRole(Role):
    pass

class LocalRole(Role):
    pass

class ClusterRoles(RBACObjects):
    def __init__(self):
        super(ClusterRoles, self).__init__()
        self.objs = self.load_objs('ClusterRole', ClusterRole)

class LocalRoles(RBACObjects):
    def __init__(self):
        super(LocalRoles, self).__init__()
        self.objs = self.load_objs('Role', LocalRole)



# Identities
class Group(RBACObject):
    def __init__(self, obj):
        super(Group, self).__init__(obj)

class Groups(RBACObjects):
    def __init__(self):
        super(Groups, self).__init__()
        self.load_objs('Group', Group)

    def get_groups_for_users(self, user_name):
        result = []
        for item in self.get_all_items():
            if user_name in item.get('users'):
                result.append(item)
        return result

    def get_group_names_for_account(self, account_name):
        result = []
        for item in self.get_groups_for_users(account_name):
            metadata = item.get('metadata')
            result.append(metadata.get('name'))
        return result

    def get_group_for_name(self, group_name):
        for item in self.get_all_items():
            metadata = item.get('metadata')
            if metadata.get('name') == group_name:
                return item
        return None

    def get_user_names_for_group(self, account_name):
        result = []
        item = self.get_group_for_name(account_name)
        if item:
            return item.get('users')
        return result

class ServiceAccount(RBACObject):
    def __init__(self, obj):
        super(ServiceAccount, self).__init__(obj)

class ServiceAccounts(RBACObjects):
    def __init__(self):
        super(ServiceAccounts, self).__init__()
        self.load_objs('ServiceAccount', ServiceAccount)

class User(RBACObject):
    def __init__(self, obj):
        super(User, self).__init__(obj)

class Users(RBACObjects):
    def __init__(self):
        super(Users, self).__init__()
        self.load_objs('User', User)


class RBACCache(object):
    def __init__(self):
        '''
        Constructor
        '''
        self.all_data = None
        self.user_objs = []
        self.group_objs = []
        self.serviceaccount_objs = []
        self.local_role_objs = []
        self.cluster_role_objs = []
        self.role_binding_objs = []
        self.cluster_role_binding_objs = []

    def load_cache(self):
        self.user_objs = Users()
        self.group_objs = Groups()
        self.serviceaccount_objs = ServiceAccounts()

        self.local_role_objs = LocalRoles()
        self.cluster_role_objs = ClusterRoles()

        self.role_binding_objs = RoleBindings()
        self.cluster_role_binding_objs = ClusterRoleBindings()

    def get_user_objs(self):
        return self.user_objs

    def get_group_objs(self):
        return self.group_objs

    def get_serviceaccount_objs(self):
        return self.serviceaccount_objs

    def get_local_role_objs(self):
        return self.local_role_objs

    def get_cluster_role_objs(self):
        return self.cluster_role_objs

    def get_role_binding_objs(self):
        return self.role_binding_objs

    def get_cluster_role_binding_objs(self):
        return self.cluster_role_binding_objs


def get_role_by_kind_name(rbac_cache, kind, name):
    for role in rbac_cache.get_cluster_role_objs().get_all() + rbac_cache.get_local_role_objs().get_all():
        if role.get_kind() == kind and role.get_metadata_name() == name:
            return role
    # FIXME fallback (potential bug in 'oc get rolebindings'
    for role in rbac_cache.get_cluster_role_objs().get_all() + rbac_cache.get_local_role_objs().get_all():
        if role.get_metadata_name() == name:
            return role
    return None

def print_identity_header(name, actype, namespace):
    if namespace:
        msg = ' namespace: ' + namespace
    else:
        msg = ''
    print '==== ' + actype + ' ' + name + msg + ' ===='

def print_roles_by_details(rbac_cache, identity_name, identity_type, identity_namespace, \
        group_names, print_roles, print_actions, output):
    # FIXME - "namespace" is different between LocalRoles and ClusterRoles
    #all_role_lines = []
    #all_action_lines = []
    for binding in rbac_cache.get_cluster_role_binding_objs().get_all() + rbac_cache.get_role_binding_objs().get_all():
        subjects = binding.get_subjects()
        for subject in subjects:
            subject_kind = subject.get('kind')
            subject_name = subject.get('name')
            subject_namespace = subject.get('namespace', "")

            # check whether this binding relevant for this identity
            if (subject_kind == identity_type and subject_name == identity_name and subject_namespace == identity_namespace) \
                or (subject_kind == 'Group' and subject_name in group_names):
                # FIXME - some groups start with "system:" and "system:serviceaccounts:"
#                 if verbose:
#                     binding.to_output('Subject kind=' + subject_kind + ' name=' + \
#                        subject_name + ' namespace=' + subject_namespace)

                # find role specified by binding's roleRef
                role = get_role_by_kind_name(rbac_cache, binding.get_roleref_kind(), binding.get_roleref_name())
                if role:
                    # which is the relevant namespace?
                    if identity_namespace:
                        overriding_namespace = identity_namespace
                    elif binding.get_metadata_namespace():
                        overriding_namespace = binding.get_metadata_namespace()
                    elif subject_namespace:
                        overriding_namespace = subject_namespace
                    else:
                        overriding_namespace = role.get_metadata_namespace()
                    if overriding_namespace == ',':
                        print overriding_namespace
                    if print_roles:
                        output.add_line(identity_type + ':' + identity_name + ' Namespace:' + overriding_namespace + \
                            ' ' + role.get_kind() + ':' + role.get_metadata_name())
                    if print_actions:
                        rules = role.get_rules()
                        for rule in rules:
                            #apiGroups = rule.get('apiGroups', [])
                            #apiGroups.sort()
                            resources = rule.get('resources', [])
                            resources.sort()
                            verbs = rule.get('verbs', [])
                            verbs.sort()
                            #print 'apiGroups:' + ','.join(apiGroups)
                            #print 'resources:' + ','.join(resources)
                            #print 'actions:' + ','.join(actions)
                            output.add_line(identity_type + ':' + identity_name + ' Namespace:' + overriding_namespace + \
                                ' Resources:' + ','.join(resources) + \
                                ' Verbs:' + ','.join(verbs))

def print_roles_for_identity(rbac_cache, identity, print_roles, print_actions, output):
    account_name = identity.get_metadata_name()
    account_type = identity.__class__.__name__
    account_namespace = identity.get_metadata_namespace()

#     print_identity_header(account_name, account_type, account_namespace)

    # get all groups
    if account_type == 'Group':
        group_names = []
    else:
        group_names = rbac_cache.get_group_objs().get_group_names_for_account(account_name)

    print_roles_by_details(rbac_cache, account_name, account_type, account_namespace, group_names, \
        print_roles, print_actions, output)

def print_roles_all_identities(rbac_cache, print_roles, print_actions, output):
    print_roles_all_users(rbac_cache, print_roles, print_actions, output)
    print_roles_all_serviceaccounts(rbac_cache, print_roles, print_actions, output)
    print_roles_all_groups(rbac_cache, print_roles, print_actions, output)

def print_roles_all_users(rbac_cache, print_roles, print_actions, output):
    for lidentity in rbac_cache.get_user_objs().get_all():
        print_roles_for_identity(rbac_cache, lidentity, print_roles, print_actions, output)

def print_roles_all_serviceaccounts(rbac_cache, print_roles, print_actions, output):
    for lidentity in rbac_cache.get_serviceaccount_objs().get_all():
        print_roles_for_identity(rbac_cache, lidentity, print_roles, print_actions, output)

def print_roles_all_groups(rbac_cache, print_roles, print_actions, output):
    for lidentity in rbac_cache.get_group_objs().get_all():
        print_roles_for_identity(rbac_cache, lidentity, print_roles, print_actions, output)

def list_names(identity_objs, output):
    for identity in identity_objs.get_all():
        output.add_line(identity.get_metadata_name())

def list_users_groups(rbac_cache, output):
    output.add_line('{:25} {}'.format('Users', 'Groups'))
    for identity in rbac_cache.get_user_objs().get_all():
        user = identity.get_metadata_name()
        group_names = rbac_cache.get_group_objs().get_group_names_for_account(user)
        output.add_line('{:25} {}'.format(user, ','.join(sorted(set(group_names)))))

def list_groups_users(rbac_cache, output):
    output.add_line('{:25} {}'.format('Groups', 'Users'))
    for identity in rbac_cache.get_group_objs().get_all():
        group = identity.get_metadata_name()
        user_names = rbac_cache.get_group_objs().get_user_names_for_group(group)
        output.add_line('{:25} {}'.format(group, ','.join(sorted(set(user_names)))))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--list', '-l', action="store", dest="arg_list", \
        help='component to list', choices=['users', 'serviceaccounts', 'groups'],)
    parser.add_argument('--user', '-u', action="store", dest="arg_user", help='user account(s)', nargs='*')
    parser.add_argument('--group', '-g', action="store", dest="arg_group", help='group account(s)', nargs='*')
    parser.add_argument('--membership', '-m', action="store_true", dest="membership", help='list group membership')
    parser.add_argument('--serviceaccount', '-s', action="store", dest="arg_serviceaccount", \
        help='service account(s)', nargs='*')
    parser.add_argument('--actions', action="store_true", dest="print_actions", default=False, \
        help='print role verbs and resources')
    parser.add_argument('--roles', action="store_true", dest="print_roles", default=False, \
        help='print roles')
#    parser.add_argument('-v', dest='verbose', action='store_true')
    args = parser.parse_args()
    
    if not args.arg_list and not args.print_actions and not args.print_roles:
        parser.exit(2, "One of the following options required: --list, --actions, --roles\n")
    
#     verbose = args.verbose

    #initialize()
    rbac_cache = RBACCache()
    rbac_cache.load_cache()

    user_objs = rbac_cache.get_user_objs()
    group_objs = rbac_cache.get_group_objs()

    output = Output()

    if args.arg_list:
        if args.arg_list.lower() == 'users':
            if args.membership:
                list_users_groups(rbac_cache, output)
            else:
                list_names(user_objs, output)
        elif args.arg_list.lower() == 'serviceaccounts':
            # assumption: serviceaccounts cannot be added to groups
            list_names(rbac_cache.get_serviceaccount_objs(), output)
        elif args.arg_list.lower() == 'groups':
            if args.membership:
                list_groups_users(rbac_cache, output)
            else:
                list_names(rbac_cache.get_group_objs(), output)
    elif args.print_roles or args.print_actions:
        if not isinstance(args.arg_user, NoneType):
            if len(args.arg_user) > 0:
                for arg in args.arg_user:
                    # user is unique for namespace
                    user = user_objs.get_obj_with_metadata_name(arg)
                    if user:
                        print_roles_for_identity(rbac_cache, user, args.print_roles, args.print_actions, output)
                    else:
                        print 'Unknown user: ' + arg
                        sys.exit(1)
            else:
                print_roles_all_users(rbac_cache, args.print_roles, args.print_actions, output)
        if not isinstance(args.arg_serviceaccount, NoneType):
            if len(args.arg_serviceaccount) > 0:
                cnt = 0
                for arg in args.arg_serviceaccount:
                    for serviceaccount in rbac_cache.get_serviceaccount_objs().get_all():
                        if serviceaccount.get_metadata_name() == arg:
                            print_roles_for_identity(rbac_cache, serviceaccount, args.print_roles, args.print_actions, output)
                    if output.get_num_lines() == cnt:
                        print 'Unknown serviceaccount: ' + arg
                        sys.exit(1)
                    cnt = output.get_num_lines()
            else:
                print_roles_all_serviceaccounts(rbac_cache, args.print_roles, args.print_actions, output)
        if not isinstance(args.arg_group, NoneType):
            if len(args.arg_group) > 0:
                for arg in args.arg_group:
                    # group is unique for namespace
                    group = group_objs.get_obj_with_metadata_name(arg)
                    if group:
                        print_roles_for_identity(rbac_cache, group, args.print_roles, args.print_actions, output)
                    else:
                        print 'Unknown group: ' + arg
                        sys.exit(1)
            else:
                print_roles_all_groups(rbac_cache, args.print_roles, args.print_actions, output)
        if isinstance(args.arg_user, NoneType) and isinstance(args.arg_serviceaccount, NoneType) \
            and isinstance(args.arg_group, NoneType):
            print_roles_all_identities(rbac_cache, args.print_roles, args.print_actions, output)
    output.print_sorted_unique()

if __name__ == '__main__':
    main()
    sys.exit(0)
