#!/bin/bash


# bash script to build the installer for Password Hash Gen.
# v 1.0.0

read -p "Version : " version
echo "Building the Password Hash Gen $version."

pyinstaller password_hash_gen.py --onefile --name "Password Hash Gen $version" --add-data="README.md:." 

echo "Build process for the Password Hash Gen $version is completed."
