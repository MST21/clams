#!/bin/sh
/home/pi/clams/.env/bin/python3 /home/pi/clams/main.py & 
/home/pi/clams/ngrok http -region=us -hostname=jordancreek.clams.dev 3000 &
/home/pi/clams/ngrok tcp --remote-addr=3.tcp.ngrok.io:21117 22 &

/usr/bin/chromium-browser --kiosk --noerrdialogs --disable-session-crashed-bubble --disable-infobars --check-for-update-interval=604800 --disable-pinch "http://localhost:3000/?&kiosk"
