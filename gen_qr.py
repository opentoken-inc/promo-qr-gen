import os
import sys
import argparse
import hmac
import qrcode
import rlp
import subprocess
import numpy as np
from tqdm import tqdm
from PIL import Image
from PIL import ImageFont
from PIL import ImageDraw
from rlp.sedes import big_endian_int, List
from rlp.exceptions import ListDeserializationError
from base64 import urlsafe_b64encode, urlsafe_b64decode

short_header_fmt = List([big_endian_int, big_endian_int])
header_fmt = List([big_endian_int, big_endian_int, big_endian_int])
_FONT_PATH = os.getenv('FONT_PATH', 'Arial.ttf')


def mkdirs_exists_ok(path):
    try:
        os.makedirs(path)
    except OSError:
        if not os.path.isdir(path):
            raise


def get_arg_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument(
        "base_url",
        type=lambda x: x.rstrip('/') + '/',
        help='The root url the QR codes will point to.')

    parser.add_argument(
        '-s',
        "--segment_id",
        type=int,
        default=0,
        help='The identifier for the segment or group of these promo codes')

    parser.add_argument(
        '-o',
        "--output_dir",
        default=None,
        help='The path to a directory where pngs will be written')

    parser.add_argument(
        '-b',
        '--begin',
        type=int,
        default=0,
        help='The first tag_id for which a qr codes will be produced')

    parser.add_argument(
        '-e',
        '--end',
        type=int,
        default=1,
        help='One greater than the last tag_id for which a qr codes will be produced')

    return parser


def validate_code(secret, code):
    code_bytes = urlsafe_b64decode(code + '===')
    if len(code_bytes) < 20:
        raise Exception('code is too short, {} < 20'.format(len(code_bytes)))
    promo_id, signature_bytes = code_bytes[:-20], code_bytes[-20:]
    sig = hmac.new(secret, promo_id, 'sha256').digest()[:20]

    if not hmac.compare_digest(sig, signature_bytes):
        raise Exception('signature does not validate')

    try:
        promo_id_data = rlp.decode(promo_id, header_fmt)
    except ListDeserializationError:
        promo_id_data = (0, *rlp.decode(promo_id, short_header_fmt))
    return promo_id_data


def create_code(secret, promo_id_data):
    promo_id = rlp.encode(promo_id_data, header_fmt)
    promo_code_bytes = promo_id + hmac.new(secret, promo_id, 'sha256').digest()[:20]
    promo_code_b64 = urlsafe_b64encode(promo_code_bytes)
    result = promo_code_b64.decode().rstrip('=')
    assert validate_code(secret, result) == promo_id_data

    return result


def stack_images(imgs):
    return Image.fromarray(np.vstack(imgs))


def generate_img(url, code):
    qr = qrcode.QRCode(box_size=20, border=6)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    text_img = Image.new('L', (img.size[0], 80), '#fff')
    draw = ImageDraw.Draw(text_img)
    font = ImageFont.truetype(_FONT_PATH, 42)
    draw.text((30, 0), code, font=font, fill='#000')

    return stack_images((np.array(img).astype(np.uint8) * 255, text_img))


def write_image(output_path, promo_id_data, img):
    file_name = 'promo-qr__{}.{}.{}.png'.format(*promo_id_data)
    path = os.path.join(output_path, file_name)
    img.save(path, 'png')


def main(argv):
    opts = get_arg_parser().parse_args(argv[1:])

    key_id = os.getenv('SECRET_KEY_ID', 0)
    secret_hex = os.getenv('SECRET_HEX')
    if not secret_hex:
        raise Exception('secret_hex is required')
    secret = bytes.fromhex(secret_hex)

    output_dir = opts.output_dir or 'qr_codes.{}.{}.{}-{}'.format(
        key_id, opts.segment_id, opts.begin, opts.end - 1)
    mkdirs_exists_ok(output_dir)
    for tag_id in tqdm(range(opts.begin, opts.end)):
        promo_id_data = (key_id, opts.segment_id, tag_id)
        code = create_code(secret, promo_id_data)
        url = opts.base_url + code
        img = generate_img(url, code)
        write_image(output_dir, promo_id_data, img)

    subprocess.check_call([
        'zip',
        '{}.zip'.format(output_dir),
        '-R',
        '{}/*'.format(output_dir),
    ])


if __name__ == '__main__':
    main(sys.argv)
