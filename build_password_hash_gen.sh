#!/bin/bash


# bash script to build the installer for Password Hash Gen.
# v 1.0.0

read -p "Version : " version
echo "Building the Password Hash Gen $version."

pyinstaller password_hash_gen.py --name "password_hash_gen$version"


zip -r "dist/password_hash_gen$version".zip "dist/password_hash_gen$version"

rm -rf "dist/password_hash_gen$version"

echo "Build process for the Password Hash Gen $version is completed."
