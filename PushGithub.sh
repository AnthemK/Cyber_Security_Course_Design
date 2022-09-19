#!/bin/bash
Now_time=$(date "+%Y-%m-%d %H:%M:%S")
echo $Now_time
git add *
git commit -m "$Now_time "
