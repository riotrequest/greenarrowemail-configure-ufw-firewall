## Securing Your GreenArrowEmail Server

To enhance the security of your GreenArrowEmail server, you can follow these steps to install and configure UFW (Uncomplicated Firewall) and Fail2Ban. This will help protect your server from unauthorized access and attacks.

# TLDR - Here it is in a single command
```
sudo apt-get update && \
sudo apt-get install ufw fail2ban -y && \
sudo ufw enable && \
sudo ufw default deny incoming && \
sudo ufw default allow outgoing && \
sudo ufw allow 25/tcp && \
sudo ufw allow 587/tcp && \
sudo ufw allow 628/tcp && \
sudo ufw allow 629/tcp && \
sudo ufw allow 110/tcp && \
sudo ufw allow 80/tcp && \
sudo ufw allow 443/tcp && \
sudo ufw allow from 127.0.0.1 && \
sudo ufw reload && \
sudo systemctl enable fail2ban && \
sudo systemctl start fail2ban
```
# Step 1: Update Package Lists
sudo apt-get update

# Step 2: Install UFW and Fail2Ban
sudo apt-get install ufw fail2ban -y

# Step 3: Configure UFW
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Open the necessary ports for GreenArrow
sudo ufw allow 25/tcp
sudo ufw allow 587/tcp
sudo ufw allow 628/tcp
sudo ufw allow 629/tcp
sudo ufw allow 110/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow all traffic from localhost
sudo ufw allow from 127.0.0.1

# Reload UFW to apply the changes
sudo ufw reload

# Step 4: Install and Start Fail2Ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

Please note that this will install Fail2Ban with its default configuration. If you have specific requirements for Fail2Ban, such as creating custom jails or modifying ban times, you should edit the configuration files located in /etc/fail2ban. Typically, you would adjust settings in the jail.local file to override the default settings in jail.conf.

By following these steps, you'll strengthen the security of your GreenArrowEmail server, helping to protect it from potential threats and unauthorized access.
