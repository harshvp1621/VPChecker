#!/bin/bash

curl -OL https://download.arangodb.com/arangodb312/DEBIAN/Release.key
sudo apt-key add - < Release.key
echo 'deb https://download.arangodb.com/arangodb312/DEBIAN/ /' | sudo tee /etc/apt/sources.list.d/arangodb.list

# Install dependencies and arangodb
sudo apt update
sudo apt install apt-transport-https arangodb3=3.12.4-1
