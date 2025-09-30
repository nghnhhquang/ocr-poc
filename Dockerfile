FROM openresty/openresty:1.27.1.2-4-alpine-fat

RUN luarocks install lua-resty-jwt && \
    luarocks install lua-resty-http && \
    luarocks install resty.jwt-validators.rsa

#docker -H "ssh://root@192.168.1.94" build -t 192.168.1.41/tatc/ocr-gateway .
#docker -H "ssh://root@192.168.1.94" push 192.168.1.41/tatc/ocr-gateway