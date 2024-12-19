#!/bin/bash

curl -i -x 127.0.0.1:8080 http://ccfit.nsu.ru/~rzheutskiy/test_files/50mb.dat --output test-output.txt

echo "50 MB file downloading finished"

curl -i -x 127.0.0.1:8080 http://ccfit.nsu.ru/~rzheutskiy/test_files/500mb.dat --output test-output.txt

echo "500 MB file downloading finished"