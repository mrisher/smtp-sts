#!/bin/bash

MMARK=../../mmark
xmlfilename=""
for file in *.md 
do 
  xmlfilename=${file%.*}.xml
  echo "Processing $file...";
  $MMARK -xml2 -page $file > $xmlfilename && xml2rfc --text $xmlfilename
done
