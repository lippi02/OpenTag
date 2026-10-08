# OpenTag
This is my project of creating and developing an opensource bluetooth tracker solution. It is developed on a seed studio XIAO-nRF52840 board. I don't know if it works on any other, I didn't have time and money to test it. I would appreciate if you tested it, you send me a feedback of your results.\
You will also need Python 3.12. Yet again, I don't know if it works on other versions, feel free to test it to it's limits.
Same goes for browsers. Chromium browsers will 100% work, but I don't know what features need to be enabled for it in any other browsers.

# How to use it:
1. Download the latest [release](https://github.com/lippi02/OpenTag/releases)
2. Unpack the downloaded ZIP file
3. Download and Install Arduino IDE
4. Install Seeed nRF52 Boards by Seeed Studio
5. Connect your board to your PC and Upload the code
6. Open Google Chrome
7. Go to: chrome://flags/#enable-experimental-web-platform-features and Enable it.\
(Task 1 to 7 needs to be done only at the first time setup)

# LocalHost option
9. Open a CMD inside the unzipped folder and run: python -m http.server 8000
10. Go back to Chrome and open: http://localhost:8000/
11. If you did everything correctly it should show you a map and some set up buttons
12. Enable location and connect to your device
13. They should show up on the map and ready to go

# Hosting it from TrueNAS
9. Install NGINX Proxy Manager Plus (Use Host Path, instead of ixVolume)
10. Create a DDNS (I used [No-IP](noip.com), but you can use whatever you want)
11. Move the index html into the NGINX's host folder eg:\\TRUENAS\apps\nginxpmplus\opentag (This is a generic location, you may have to change it according to your setup)
12. Create a Proxy Host, where: Domain Name {Your DDNS}; Scheme: path:; Forward Hostname / IP / Path: /data/opentag/ (You may have to change it according to your setup); Leave everything else as is
13. Switch to TLS, Request a new Certificate; Force HTTPS; Leave everything else as is\
    (You may have to open a port on your router if NGINX throws an error: (This may differ between manufacturers))
    1. Service name: OpenTag HTTP; Protocol TCP; Internal host: {Your Truenas IP Address}; External port: 80, Internal port: 30361 (This is the default port, that NGINX uses, your may differ according to your setup)
    2. Service name: OpenTag HTTP; Protocol TCP; Internal host: {Your Truenas IP Address}; External port: 443, Internal port: 30362 (This is the default port, that NGINX uses, your may differ according to your setup)
14. If you did everything right and click on Save, your DDNS Address should be accessible and now you can see your OWN hosted website
