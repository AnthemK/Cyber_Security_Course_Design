#!/bin/bash
Now_time=$(date "+%Y-%m-%d %H:%M:%S")
echo $1
git add *
git commit -m "$Now_time:""$1"
git push origin main
