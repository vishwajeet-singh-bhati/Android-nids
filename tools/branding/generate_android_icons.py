"""Resize the approved logo into Android resources; no model or network access."""
import argparse
from pathlib import Path
from PIL import Image


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path('docs/branding/rakshak-logo.png'))
    parser.add_argument('--res', type=Path, default=Path('android/app/src/main/res'))
    args = parser.parse_args()
    original = Image.open(args.source).convert('RGBA')
    mark = original.crop(original.getchannel('A').getbbox())

    def canvas(size, fraction, background):
        result = Image.new('RGBA', (size, size), background)
        symbol = mark.copy()
        symbol.thumbnail((round(size * fraction), round(size * fraction)), Image.Resampling.LANCZOS)
        result.alpha_composite(symbol, ((size-symbol.width)//2, (size-symbol.height)//2))
        return result

    for density, size in [('mdpi',48),('hdpi',72),('xhdpi',96),('xxhdpi',144),('xxxhdpi',192)]:
        folder = args.res / ('mipmap-' + density)
        folder.mkdir(parents=True, exist_ok=True)
        canvas(size, .70, 'white').save(folder / 'ic_launcher.png')
    folder = args.res / 'drawable-nodpi'
    folder.mkdir(parents=True, exist_ok=True)
    # 60% of the 108dp adaptive canvas fits Android's central safe zone.
    foreground = canvas(432, .60, (0,0,0,0))
    foreground.save(folder / 'rakshak_foreground.png')
    mono = Image.new('RGBA', foreground.size, 'white')
    mono.putalpha(foreground.getchannel('A'))
    mono.save(folder / 'rakshak_monochrome.png')
    canvas(256, .88, (0,0,0,0)).save(folder / 'rakshak_logo.png')
    print('Generated launcher densities, adaptive foreground, monochrome and header logo.')


if __name__ == '__main__':
    main()
