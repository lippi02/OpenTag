# OpenTag
This is my project of creating and developing an opensource bluetooth tracker solution. It is developed on a seed studio XIAO-nRF52840 board. I don't know if it works on any other, I didn't have time and money to test it.I would appreciate if you test it and give me a feedback.
You will also need Python 3.12. Yet again, I don't know if it works on other versions, feel free to test it to it's limits.
Same goes for browsers. Chromium browsers will 100% work, but I don't know what features need to be enabled for it.

# How to use it:
1. Download the latest [release](https://github.com/lippi02/OpenTag/releases)
2. Unpack the downloaded ZIP file
3. Download and Install Arduino IDE
4. Install Seeed nRF52 Boards by Seeed Studio
5. Connect your board to your PC and Upload the code
6. Open Google Chrome
7. Go to: chrome://flags/#enable-experimental-web-platform-features and Enable it.\
(Task 1 to 7 needs to be done only at the first time setup)
8. Open a CMD inside the unzipped folder and run: python -m http.server 8000
9. Go back to Chrome and open: http://localhost:8000/
10. If you did everything correctly it should show you a map and some set up buttons
11. Enable location and connect to your device
12. They should show up on the map and ready to go
