#!/bin/bash
# Quick build command

python3 auto_build.py && echo -e "\n\n✅ BUILD COMPLETE! Now run:\n   git add dist/\n   git commit -m '🚀 Add Windows Executables'\n   git push origin main\n"
