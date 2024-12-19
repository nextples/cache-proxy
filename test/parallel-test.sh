#!/bin/bash

if [ -z "$1" ]; then
  echo "Ошибка: не указан параметр n"
  exit 1
fi

n=$1

for ((i=0; i < n; i++))
do
  curl -i -x 127.0.0.1:8080 http://www.google.com &
done

wait

echo
echo
echo
echo "Все запросы выполнены"