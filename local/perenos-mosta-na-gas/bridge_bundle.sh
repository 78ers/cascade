set -euo pipefail
W=/root/ph2-bundle; rm -rf $W; mkdir -p $W; chmod 700 $W
cp /etc/cascade/config.json $W/config.json
cp /etc/cascade/panel_secret $W/panel_secret
cp /etc/nginx/nginx.conf $W/nginx.conf
cp /etc/caddy/conf.d/cascade-panel.caddy $W/cascade-panel.caddy
cp "$(systemctl show cascade-panel -p FragmentPath --value)" $W/cascade-panel.service
tar -czf $W/caddy-data.tgz -C /var/lib/caddy/.local/share caddy
iptables-save -t nat | grep -E '^-A PREROUTING .*--dport (8454|8464|8474) -j DNAT' > $W/dnat.txt
[ "$(wc -l < $W/dnat.txt)" = "3" ] || { echo "ожидалось 3 правила DNAT, найдено $(wc -l < $W/dnat.txt)"; exit 1; }
{
echo '*filter'; echo ':FORWARD DROP [0:0]'
echo '-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
echo '-A FORWARD -m conntrack --ctstate DNAT -j ACCEPT'
echo 'COMMIT'
echo '*nat'; echo ':PREROUTING ACCEPT [0:0]'; echo ':INPUT ACCEPT [0:0]'; echo ':OUTPUT ACCEPT [0:0]'; echo ':POSTROUTING ACCEPT [0:0]'
cat $W/dnat.txt
echo '-A POSTROUTING -o ens34 -m conntrack --ctstate DNAT -j MASQUERADE'
echo 'COMMIT'
echo '*mangle'; echo ':FORWARD ACCEPT [0:0]'
echo '-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340'
echo 'COMMIT'
} > $W/nat.rules
rm -f $W/dnat.txt
tar -czf /root/ph2-bundle.tgz -C /root ph2-bundle
rm -rf $W
chmod 600 /root/ph2-bundle.tgz
ls -l /root/ph2-bundle.tgz | awk '{print "пакет:", $5, "байт"}'
