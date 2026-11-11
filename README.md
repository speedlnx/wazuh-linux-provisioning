# wazuh-linux-provisioning
Script per configurare le notifiche telegram sul mio wazuh


Una volta scaricato esegui:

bash -n /root/wazuh-linux-provision-v2.1.sh \
  && echo "Sintassi Bash OK"


chmod 700 /root/wazuh-linux-provision-v2.1.sh
bash /root/wazuh-linux-provision-v2.1.sh

# Per testare una notifica: 

TEST_USER="wazuh-test-$(date +%s)"

printf '{"integration":"privilege_monitor","privilege_category":"sudo_users","action":"added","user":"%s","host":"%s"}\n' \
  "$TEST_USER" "$(hostname)" \
  >> /var/log/wazuh-privileges.log

echo "Utente di test: $TEST_USER"
