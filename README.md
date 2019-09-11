python-rbaclist
===========

The goal of this project is to provide useful information about OpenShift users, groups and service accounts as well as the roles (verbs and resources) that they are permitted to access.

## Installation
The tool is written in Python and uses the Python "json" library.

The tool executes the "oc" command. "oc" should be used to login to OpenShift with the "system:admin" user before running the "rbaclist" command.

## List 
- rbaclist -l users
- rbaclist -l groups
- rbaclist -l serviceaccounts

## List With Group or User Membership
- rbaclist -l users -m
- rbaclist -l groups -m 
- rbaclist -l serviceaccounts -m

## List Roles for All Users, Groups and/or Service Accounts
- rbaclist --role
- rbaclist --role -u
- rbaclist --role -g
- rbaclist --role -s

## List Roles for a Specific User Group or Service Account
- rbaclist --role -u &lt;*user*> \[...&lt;*usern*>]
- rbaclist --role -g &lt;*group*> \[...&lt;*groupn*>]
- rbaclist --role -s &lt;*serviceaccount*> \[...&lt;*serviceaccountn*>]

## List Actions (resources and verbs) for All Users, Groups and/or Service Accounts
- rbaclist --actions
- rbaclist --actions -u
- rbaclist --actions -g
- rbaclist --actions -s

## List Actions (resources and verbs) for a Specific User Group or Service Account
- rbaclist --actions -u &lt;*user*> \[...&lt;*usern*>]
- rbaclist --actions -g &lt;*group*> \[...&lt;*groupn*>]
- rbaclist --actions -s &lt;*serviceaccount*> \[...&lt;*serviceaccountn*>]
