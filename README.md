# Security Utils (v.1.0.0)

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