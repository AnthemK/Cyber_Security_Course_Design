#!/bin/bash
Now_time=$(date "+%Y-%m-%d %H:%M:%S")
echo $1
cd ./Code/Kernel_Part
# hou mian yao ti huan cheng  make
git add *
git commit -m "$Now_time:"" $1"
git push origin main
