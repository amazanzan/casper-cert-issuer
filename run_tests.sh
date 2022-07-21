#!/bin/bash

for file in ./tests/*; do
  [ -f "$file" ] || continue
  echo "Running $file..."
  #  python [option] -- "$file"
  python -- "$file"
done