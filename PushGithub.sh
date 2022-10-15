#!/bin/bash
Now_time=$(date "+%Y-%m-%d %H:%M:%S")
commit_msg="$Now_time:"" $1"
echo commit message will be: $commit_msg
# hou mian yao ti huan cheng  make
echo clean syx\'s project
make -s -C Other_Project/syx clean #clean syx 
git add *
git commit -m "$commit_msg"
git push origin main
