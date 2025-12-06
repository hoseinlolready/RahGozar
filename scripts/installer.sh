GREEN='\033[0;32m'
NC='\033[0m'
ip=$(curl -s https://api.ipify.org)

echo -e "${GREEN}Installing The Packages...${NC}"

apt install curl wget python3 python3-pip -y

echo -e "${GREEN}Installing Rahgozar Panel...${NC}"

mkdir -p /opt/Rahgozar/

echo -e "${GREEN}Downloading the Rahgozar Files...${NC}"

wget -P /opt/Rahgozar/ https://raw.githubusercontent.com/hoseinlolready/RahGozar/refs/heads/main/codes/panel.py
wget -P /opt/Rahgozar/ https://raw.githubusercontent.com/hoseinlolready/RahGozar/refs/heads/main/codes/core.py
wget -P /opt/Rahgozar/ https://raw.githubusercontent.com/hoseinlolready/RahGozar/refs/heads/main/codes/main.py
wget -P /opt/Rahgozar/ https://raw.githubusercontent.com/hoseinlolready/RahGozar/refs/heads/main/code/script.py

echo -e "${GREEN}Setuping the Rahgozar Panel...${NC}"

chmod +x /opt/Rahgozar/script.py
sed -i 's/\r$//' /opt/Rahgozar/script.py
sudo ln -s /opt/Rahgozar/script.py /usr/bin/Rahgozar


cat > /etc/systemd/system/Rahgozar.service <<EOF
[Unit]
Description=Rahgozar Manager
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/Rahgozar
ExecStart=/usr/bin/python3 /opt/Rahgozar/main.py run
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}Running Rahgozar ${NC}"

systemctl daemon-reload
systemctl enable --now Rahgozar

echo -e "${GREEN}------------------------------------------------${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "1. Create your admin user:"
echo -e "    Rahgozar add admin 123456"
echo -e ""
echo -e "2. Access the panel:"
echo -e "   http://localhost:9090"
echo -e "   http://$ip:9090"
echo -e "${GREEN}------------------------------------------------${NC}"
