#!/bin/bash

for file in ./*.py; do
  [ -f "$file" ] || continue
  echo "Running $file..."
  #  python [option] -- "$file"
  python -- "$file"
done