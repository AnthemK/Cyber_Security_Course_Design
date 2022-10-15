#!/bin/bash
Now_time=$(date "+%Y-%m-%d %H:%M:%S")
echo commit message will be: "$Now_time:"" $1"
# hou mian yao ti huan cheng  make
echo clean syx\'s project
make -s -C Other_Project/syx clean #clean syx 
git add *
git commit -m "$Now_time:"" $1"
git push origin main
