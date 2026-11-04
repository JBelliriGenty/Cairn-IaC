# cairn-iac server: Python + PyYAML + git/ssh, run as nobody.
#   docker build -t cairn-iac . && docker run -v ./config.json:/etc/cairn-iac/config.json:ro -v cairn-iac:/var/lib/cairn-iac cairn-iac
FROM alpine:3.22
RUN apk add --no-cache python3 py3-yaml git openssh-client
COPY cairn-iac.py page.html /app/
ENV PYTHONDONTWRITEBYTECODE=1 HOME=/var/lib/cairn-iac
RUN mkdir -p /var/lib/cairn-iac && chown nobody:nobody /var/lib/cairn-iac
USER nobody
ENTRYPOINT ["python3", "/app/cairn-iac.py", "--serve", "-c"]
CMD ["/etc/cairn-iac/config.json"]
