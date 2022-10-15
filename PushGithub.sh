#!/bin/bash
Now_time=$(date "+%Y-%m-%d %H:%M:%S")
echo $Now_time + $1
# hou mian yao ti huan cheng  make
make -C Code/Other_Project/syx clean #clean syx 
git add *
git commit -m "$Now_time:"" $1"
git push origin main
