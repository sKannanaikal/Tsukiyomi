#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
sudo apt update
sudo apt install apache2 -y
sudo apt install git -y
sudo systemctl start apache2
sudo systemctl enable apache2
sudo apt install mysql-server -y
sudo apt install php libapache2-mod-php php-mysql -y
sudo systemctl start mysql
sudo systemctl enable mysql
sudo cp ./dir.conf /etc/apache2/mods-enabled/dir.conf
sudo cp ./info.php /var/www/html/info.php
sudo cp ./index.php /var/www/html/index.php
sudo cp ./connect-db.php /var/www/html/connect-db.php
sudo cp ./login.php /var/www/html/login.php
sudo cp ./home.php /var/www/html/home.php
sudo cp ./uploader.php /var/www/html/uploader.php
sudo cp ./apache2.conf /etc/apache2/apache2.conf
sudo mkdir /opt/scripts
sudo cp ./store-logs.sh /opt/scripts/store-logs.sh
sudo chmod 777 /opt/scripts/store-logs.sh
sudo systemctl restart apache2
mkdir /var/www/html/uploads
sudo chown www-data:www-data /var/www/html/uploads && sudo chmod 777 /var/www/html/uploads
mysql -h localhost -u root < ./create-db.sql
sudo systemctl restart mysql