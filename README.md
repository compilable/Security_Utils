# Security Utils (v.1.0.0)

## Development Setup:
- Setup the venv:
```
python3 -m venv .venv
```
- Activate the local venv:
```
source .venv/bin/activate
```
- Install requirements:
```
pip install -r requirements.txt
```

## Image Content Randomizer:
- Can be used to alter the image content by slightly changing Pixcel content to add a hidden signature. 

```
python3 image_randomizer img/folder
```

## Password hash generator GUI :
Can be used to generate a hash by using a combination of seeds including key files, and multiple text values.
Can use the password to generate the HMAC on the generated hashes.

```
python3 password_hash_gen.py
```

![Password hash generator GUI v1.0.0](https://raw.githubusercontent.com/compilable/Security_Utils/refs/heads/main/res/screenshot_password_hash_gen_v1.0.0.png)

### Algorithm:
1. generate the hash of each file (iterate by number of times).
2. generate the hash of the q1,q2,q3 (if exists) (iterate by number of times).
3. use the password as the HAMC key to generate the final hash of the combind hashs:
    `(files_hash + q1_hash + q2_hash + q3_hash) , password`


### ToDO:
- Create a make file / bash script to generate the `pyinstaller` .
```
 pyinstaller password_hash_gen.py --name password_hash_gen_v1.0.0
 ```
- Add unit-tests for each hash/encryption function.
- Allow adding a signature to image files. (Steganography)

### Resources:
- [pyinstaller user guide](https://pyinstaller.org/en/stable/usage.html)
- [online hasing tools](https://emn178.github.io/online-tools/)
- [test resources](https://github.com/spothq/cryptocurrency-icons/tree/master)