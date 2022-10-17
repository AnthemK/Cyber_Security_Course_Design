#!/bin/bash

Now_time=$(date "+%Y-%m-%d %H:%M:%S")
if [ -z "$#" ]
then
      commit_msg="Updated on $Now_time"
else
      commit_msg="$Now_time:"" $*"
fi
echo commit message will be:
echo $commit_msg
# hou mian yao ti huan cheng  make

#echo clean syx\'s project
#make -s -C Other_Project/syx clean #clean syx 

echo clean lwz\'s project
make -s -C Code clean

git add *
git commit -m "$commit_msg"
git push origin main
