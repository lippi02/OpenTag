# OpenTag
This is my project of creating and developing an opensource bluetooth tracker solution. It is developed on a seed studio XIAO-nRF52840 board. I don't know if it works on any other, I didn't have time and money to test it. I would appreciate if you tested it, you send me a feedback of your results.\
Same goes for browsers. Chromium browsers will 100% work, but I don't know what features need to be enabled for it in any other browsers.

# How to just use it:
 1. Download the latest [release](https://github.com/lippi02/OpenTag/releases)
 2. Unpack the downloaded ZIP file

## Firmware Setup
 3. Download and Install Arduino IDE
 4. Install the Seeed nRF52 Boards package.
 5. Open `firmware/OpenTag.ino`.
 6. Select Seeed XIAO nRF52840 and upload the sketch.
 7. Flash this firmware to each tracker you want to identify consistently across browsers/devices.

## Browser Setup
 8. Open a Chromium-base browser
 9. Go to: chrome://flags/#enable-experimental-web-platform-features and Enable it.
 10. Grant location permission to display the current phone location and calculate distance to tracker-reporter locations.
 11. Use **Add tracker** in the hamburger menu. The browser opens a Bluetooth chooser; choose one OpenTag device. Repeat for each tracker.\
(The current browser listens to one selected tracker at a time. Use a tracker's **Connect** button to switch the active BLE listener. All registered trackers and their last-known positions remain on the map.)

# Hosting your own from TrueNAS
 9. Install NGINX Proxy Manager Plus (Use Host Path, instead of ixVolume)
 10. Create a Custom App for the backend (Discover Apps, 3 dot, Install via YML) using the truenas-custom-app.yaml
 11. Create a DDNS (I used [No-IP](noip.com), but you can use whatever you want)
 12. Move the opentag folder into the NGINX's host folder eg: "\\TRUENAS\apps\nginxpmplus\opentag" *(This is a generic location, you may have to change it according to your setup)*
 13. Create a Proxy Host, where: Domain Name {Your DDNS}; Scheme: "path:" ; Forward Hostname / IP / Path: "/data/opentag/webapp/" *(You may have to change it according to your setup)*; Leave everything else as is
 14. Go to Custom Locations /path: "/ws/"; Scheme: "http://"; Forward Hostname / IP / Path: {Your NAS' IP}; Forward Port: "3000"
 16. Scroll down and click on "Add Location", then fill everything as in step 14, but /path: should be /api/ instead of /ws/
 17. Switch to TLS, In the dropdown menu select "Request a new Certificate"; and check "Force HTTPS"; Leave everything else as is\
    *(You may have to open a port on your router if NGINX throws an error: (This may differ between manufacturers)*
     1. *Service name: OpenTag HTTP; Protocol TCP; Internal host: {Your Truenas IP Address}; External port: 80, Internal port: 30361 (This is the default port, that NGINX uses, your may differ according to your setup)*
     2. *Service name: OpenTag HTTPS; Protocol TCP; Internal host: {Your Truenas IP Address}; External port: 443, Internal port: 30362 (This is the default port, that NGINX uses, your may differ according to your setup))*
 19. If you did everything right and click on Save, your DDNS Address should be accessible and now you can see your OWN hosted website\
*(You may also have to setup a DDNS service in your router to prevent a non-accessible website, because your ISP changed your public IP. But the process differs between manufacturers)*
