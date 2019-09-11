# Users: developer
# Groups: programmers
# ServiceAccounts: michael-sa
create_accounts() {
	oc create user u-developer
	oc create identity anypassword:u-developer
	oc create user u-smarterdeveloper
	oc create identity anypassword:u-smarterdeveloper
	oc adm groups new g-programmers u-developer
	oc adm groups new g-smarterprogrammers u-smarterdevelopers
        oc adm groups new g-allemployees u-developer
	oc adm groups add-users g-allemployees u-smarterdeveloper
	oc create serviceaccount sa-myserviceaccount

	oc create role r-smartpeople --verb=get --resource=pod -n default
	oc adm policy add-role-to-user r-smartpeople u-smarterdeveloper --role-namespace=default -n default

	oc create clusterrole cr-smartadmins --verb=get --resource=services
	oc adm policy add-cluster-role-to-user cr-smartadmins u-developer

	oc create role r-smartpeople-endpoints --verb=get --resource=endpoints
	oc adm policy add-role-to-group r-smartpeople-endpoints g-programmers  --role-namespace=default -n default

	oc create clusterrole cr-smartpeople-nodes --verb=get --resource=nodes
	oc adm policy add-cluster-role-to-group cr-smartpeople-nodes g-allemployees

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
run_test --roles -u u-developer
run_test --roles -u
run_test --roles -g g-programmers
run_test --roles -g
run_test --roles -s default-rolebindings-controller
run_test --roles -s
run_test --actions
run_test --actions -u u-developer
run_test --actions -u
run_test --actions -g g-programmers
run_test --actions -g
run_test --actions -s default-rolebindings-controller
run_test --actions -s
