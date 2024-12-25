#!/bin/bash

if [ -z "$1" ]; then
  echo "Ошибка: не указан параметр n"
  exit 1
fi

n=$1

for ((i=0; i < n; i++))
do
  curl -i --http1.0 -x 127.0.0.1:8081 http://parallels.nsu.ru &
done

wait

echo
echo
echo
echo "Все запросы выполнены"