from PIL import Image


def thumb(src, dst):
    Image.open(src).resize((128, 128)).save(dst)
