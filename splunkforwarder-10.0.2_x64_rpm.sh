# 1. Download the Universal Forwarder RPM package
wget -O splunkforwarder-10.0.2-e2d18b4767e9.x86_64.rpm "https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9.x86_64.rpm"
#Verification: ls -lh splunkforwarder-10.0.2-e2d18b4767e9.x86_64.rpm

# 2. Install the package silently using yum or rpm
sudo rpm -i splunkforwarder-10.0.2-e2d18b4767e9.x86_64.rpm
#Verification: rpm -q splunkforwarder

# 3. Start Splunk and accept the license automatically
sudo /opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt
#Verification: sudo /opt/splunkforwarder/bin/splunk status

# 4. Point the forwarder to your Debian Splunk collector
sudo /opt/splunkforwarder/bin/splunk add forward-server 172.20.240.20:9997
#Verification: sudo /opt/splunkforwarder/bin/splunk list forward-server
