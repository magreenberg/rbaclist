python-rbac
===========

The goal of this project is to provide useful information about OpenShift users, groups and service accounts as well as the roles (verbs and resources) that they are permitted to access.

## Installation
The tool is written in Python and uses the Python "json" library.

The tool executes the "oc" command. "oc" should be used to login to OpenShift with the "system:admin" user before running the "rbac" command.

## List 
- rbac -l users
- rbac -l groups
- rbac -l serviceaccounts

## List With Group or User Membership
- rbac -l users -m
- rbac -l groups -m 
- rbac -l serviceaccounts -m

## List Roles for All Users, Groups and/or Service Accounts
- rbac --role
- rbac --role -u
- rbac --role -g
- rbac --role -s

## List Roles for a Specific User Group or Service Account
- rbac --role -u &lt;*user*> \[...&lt;*usern*>]
- rbac --role -g &lt;*group*> \[...&lt;*groupn*>]
- rbac --role -s &lt;*serviceaccount*> \[...&lt;*serviceaccountn*>]

## List Actions (resources and verbs) for All Users, Groups and/or Service Accounts
- rbac --actions
- rbac --actions -u
- rbac --actions -g
- rbac --actions -s

## List Actions (resources and verbs) for a Specific User Group or Service Account
- rbac --actions -u &lt;*user*> \[...&lt;*usern*>]
- rbac --actions -g &lt;*group*> \[...&lt;*groupn*>]
- rbac --actions -s &lt;*serviceaccount*> \[...&lt;*serviceaccountn*>]
