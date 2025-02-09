from PIL import Image
import random
import os
import hashlib
import sys

CYCEL_COUNT=5
OVERRIDE_ORIGINAL=True

def md5checksum(fname):
    md5 = hashlib.md5()
    with open(fname, "rb") as f:
        while chunk := f.read(4096):
            md5.update(chunk)
    return md5.hexdigest()

def convert_image(img_fq_path, overwrite= OVERRIDE_ORIGINAL):


    if not os.path.exists(img_fq_path):
        print('The file does not exist')
        return
    original_hash = md5checksum(img_fq_path)

    file_name = os.path.basename(img_fq_path)

    img = Image.open(img_fq_path)
    
    width, height = img.size
    stepper = random.randint(1, 10)
    for x in range(0,width, stepper):
        for y in range(0,height, stepper):
            new_rgb = rand_color(img.getpixel((x, y)))
            #print(F"{img.getpixel((x, y))} ' -> ' {new_rgb}")
            img.putpixel((x, y), new_rgb)

    if not overwrite:
        new_file = os.path.splitext(file_name)
        new_file_name = F"{new_file[0]}_x{new_file[1]}"
        path = os.path.join(os.path.dirname(img_fq_path), new_file_name)
    else:
        path= img_fq_path

    img.save(path)

    print(F'file hash {original_hash} -> {md5checksum(path)}')

def rand_color(current_pix, range_stepper=5):

    if not isinstance(current_pix, list):
        return current_pix
    rgb = list()
    rgb.append(current_pix[0])   
    rgb.append(current_pix[1])   
    rgb.append(current_pix[2])   

    for position in range(0,3):

        if range_stepper > current_pix[position]:
            start = current_pix[position] + range_stepper
        else:
            start = current_pix[position] - range_stepper

            rgb[position] = random.randint(start ,current_pix[position])

    return tuple(rgb)

def process_img_in_dir(fq_dir_path):
    if not os.path.exists(fq_dir_path):
        print('The folder does not exist')
        return
    
    files = [f for f in os.listdir(fq_dir_path) if os.path.isfile(os.path.join(fq_dir_path, f))]
  
    for file in files:
        file_path = os.path.join(fq_dir_path,file)
        print(F'processing the file {file_path}')

        for index in range(0,CYCEL_COUNT):
            convert_image(file_path,True)

if __name__ == "__main__":
    if  len(sys.argv) == 1:
        print('The folder path is missing')
        exit()
    
    fq_path = sys.argv[1]
    print("Folder path to process :", fq_path)
    process_img_in_dir(fq_path)