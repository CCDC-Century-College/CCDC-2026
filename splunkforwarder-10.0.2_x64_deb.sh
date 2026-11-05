# 1. Download the Universal Forwarder DEB package
wget -O splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb "https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb"
#Verification: ls -lh splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb

# 2. Install the package using dpkg
sudo dpkg -i splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb
#Verification: dpkg -l | grep splunkforwarder

# 3. Start Splunk and accept the license automatically
sudo /opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt
#Verification: sudo /opt/splunkforwarder/bin/splunk status

# 4. Point the forwarder to your Debian Splunk collector
sudo /opt/splunkforwarder/bin/splunk add forward-server 17.20.240.20:9997 -auth admin:PLACEHOLDER
#Verification: sudo /opt/splunkforwarder/bin/splunk list forward-server
