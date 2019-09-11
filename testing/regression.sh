# Users: developer
# Groups: programmers
# ServiceAccounts: michael-sa
create_accounts() {
	oc create user developer
	oc create identity anypassword:developer
	oc create user smarterdeveloper
	oc create identity anypassword:smarterdeveloper
	oc adm groups new programmers developer
	oc adm groups new smarterprogrammers smarterdevelopers
        oc adm groups new allemployees developer
        oc adm groups add-users allemployees smarterdevelopers
	oc create serviceaccount mybot

	oc create role smartpeople --verb=get --resource=pod -n default
	oc adm policy add-role-to-user smartpeople smarterdeveloper
}

run_test() {
	echo "= ./rbac $*="
	eval ./rbaclist $*
	if [ $? -ne 0 ];then
		echo "FAILED: ./rbaclist $*" 1>&2
	fi
}
echo "== list =="
run_test -l users
run_test -l users -m
run_test -l groups
run_test -l groups -m
run_test -l serviceaccounts
run_test -l serviceaccounts -m
run_test --roles
run_test --roles -u developer
run_test --roles -u
run_test --roles -g programmers
run_test --roles -g
run_test --roles -s deployer
run_test --roles -s
run_test --actions
run_test --actions -u developer
run_test --actions -u
run_test --actions -g programmers
run_test --actions -g
run_test --actions -s deployer
run_test --actions -s
