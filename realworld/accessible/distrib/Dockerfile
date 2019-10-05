FROM ubuntu:latest
MAINTAINER i@shiki7.me

# OPTIONAL: Switch source
RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/jp.archive.ubuntu.com/g" /etc/apt/sources.list

# install packages
RUN apt update && apt upgrade -y
RUN apt install -y ca-certificates fonts-liberation libappindicator3-1 libasound2 libatk-bridge2.0-0 libatk1.0-0 libatspi2.0-0 libc6 libcairo2 libcups2 libdbus-1-3 libexpat1 libgcc1 libgdk-pixbuf2.0-0 libglib2.0-0 libgtk-3-0 libnspr4 libnss3 libpango-1.0-0 libpangocairo-1.0-0 libuuid1 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 libxtst6 wget xdg-utils

# install custom chrome
ADD ./chromium-browser-stable_79.0.3912.0-1_amd64.deb /tmp/
RUN dpkg --install /tmp/chromium-browser-stable_79.0.3912.0-1_amd64.deb

# add flag to /
ADD ./flag /flag
RUN chmod 644 /flag

CMD ["/bin/bash"]

