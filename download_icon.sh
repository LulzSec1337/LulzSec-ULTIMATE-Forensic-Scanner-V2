#!/bin/bash

echo "🎨 Downloading and preparing icon..."

# Download the icon
wget -q "https://img.favpng.com/12/4/9/lulzsec-security-hacker-anonymous-computer-security-hacker-group-png-favpng-6dhsmimztz2KE7GidS52k9VNS.jpg" -O lulzsec_icon.jpg

# Convert to ICO (Windows icon format) using ImageMagick
if command -v convert &> /dev/null; then
    echo "✅ Converting to .ico format..."
    convert lulzsec_icon.jpg -resize 256x256 lulzsec_icon.ico
    echo "✅ Icon created: lulzsec_icon.ico"
elif command -v magick &> /dev/null; then
    echo "✅ Converting to .ico format..."
    magick lulzsec_icon.jpg -resize 256x256 lulzsec_icon.ico
    echo "✅ Icon created: lulzsec_icon.ico"
else
    echo "⚠️  ImageMagick not found, installing..."
    sudo apt-get update -qq
    sudo apt-get install -y imagemagick
    convert lulzsec_icon.jpg -resize 256x256 lulzsec_icon.ico
    echo "✅ Icon created: lulzsec_icon.ico"
fi

# Clean up temp file
rm -f lulzsec_icon.jpg

echo ""
echo "✅ Icon ready for build scripts!"
