set -euo pipefail
. /root/cascade-ph2/guard.sh
[ -d /opt/cascade ] || git clone -q https://github.com/78ers/cascade.git /opt/cascade
git -C /opt/cascade checkout -q 69ae045
git -C /opt/cascade config core.pager cat
nice -n 10 python3 -m venv /opt/cascade/.venv
nice -n 10 /opt/cascade/.venv/bin/pip install --quiet -e /opt/cascade
printf '#!/bin/bash\nexec "/opt/cascade/.venv/bin/python" -m cascade "$@"\n' > /usr/local/bin/cascade; chmod 755 /usr/local/bin/cascade
install -d -m 700 /etc/cascade
/opt/cascade/.venv/bin/python --version
cd /opt/cascade && PYTHONPATH=/opt/cascade /opt/cascade/.venv/bin/python -c "import cascade.config, cascade.xray_config, cascade.relay, cascade.panel.app; print('импорт модулей: ok')"
echo "коммит: $(git -C /opt/cascade rev-parse --short HEAD); venv: $(du -sm /opt/cascade | cut -f1) МБ"
