#!/bin/bash
# I want to keep THEIR version when there is a conflict
# Swap files: %A (the second parameter) contains my version
cp -f $3 $2

# Indicate the merge has been successfully "resolved" with the exit
# status
exit 0
