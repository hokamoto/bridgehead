# Bridgehead

## Dockerのインストール
https://docs.docker.com/install/

## Dockerイメージの作成と実行
```
$ docker build -t bridgehead .
$ docker run -i bridgehead < sample_urls.txt > output.csv
```