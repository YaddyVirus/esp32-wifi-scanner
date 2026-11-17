# ESP32 Wi-Fi Scanner

A small Arduino sketch that turns a regular ESP32 into an always-on 2.4 GHz Wi-Fi analyzer with its own webpage.

- **Scans the whole 2.4 GHz band every 5 seconds**, all day, and logs every result
- **Lists every access point** it can hear: SSID, BSSID, channel, security and signal strength
- **Charts channel congestion** across channels 1–13, with your own network's channel highlighted
- **Logs neighbors switching channels**, so you can leave it running overnight and see who hops where
- **Spots client devices in promiscuous mode** from probe requests and data frames, and flags randomized MAC addresses (one phone can show up as several "devices")
- **Serves it all on a webpage** on your local network that refreshes every 3 seconds, plus a one-line summary per scan on the Serial Monitor

## What you need

- Any ESP32 dev board with the original ESP32 chip (e.g. ESP32 DevKit V1 / ESP32-WROOM-32). Tested on an ESP32-D0WD-V3 board.
- A USB data cable
- A Wi-Fi network with a **2.4 GHz** band (the ESP32 can't join or scan 5 GHz)
- [Arduino IDE 2.x](https://www.arduino.cc/en/software)

## Setup

1. **Install ESP32 support in the Arduino IDE.** Open **Tools > Board > Boards Manager**, search for **esp32**, and install **esp32 by Espressif Systems**. Tested with version 3.3.11.
2. **Get the sketch.** Clone this repo or use **Code > Download ZIP** and extract it. The `.ino` file has to sit in a folder with the same name (`esp32-wifi-scanner`). If you open it from `esp32-wifi-scanner-main`, the IDE will offer to move it into the right folder, so click OK.
3. **Open `esp32-wifi-scanner.ino`** in the Arduino IDE.
4. **Add your Wi-Fi details** near the top of the sketch:
   ```cpp
   const char *WIFI_SSID = "your-network-name";
   const char *WIFI_PASS = "your-wifi-password";
   ```
5. **Pick the board and port.** Plug in the ESP32. From the board dropdown choose **Select other board and port**, then pick **ESP32 Dev Module** and your board's COM port.
6. **Upload.** Click the right-arrow Upload button. Some boards need you to hold the **BOOT** button when "Connecting..." appears.
7. **Find the IP address.** Open **Tools > Serial Monitor** and set it to **115200 baud**. Press the board's **EN/RST** button and you'll see:
   ```
   Connected, open http://192.168.x.x
   scan #1: 13 APs in 3430 ms | ch1:6 ch5:2 ch6:2 ch11:3
   ```
8. **Open that address** in a browser on any device on the same network.

## Reading the page

| Panel | What it shows |
|---|---|
| Header | Scan count, scan interval, how long the last sweep took, uptime and free RAM |
| Access points | Every network heard in the last sweep, strongest first. Your own network is in green. |
| Channel congestion | How many networks sit on each 2.4 GHz channel. Your channel is the green bar. Channels 1, 6 and 11 don't overlap, so pick whichever of those is least crowded. |
| Client devices | Phones, laptops and other gadgets the ESP32 overheard. **probe request** means a device was searching for networks; **data** means it was talking to an access point. **randomized** marks a MAC address the device made up for privacy. |
| Scan log | The last 40 events, newest first, including any network that moved channel |

## Customizing

- `SCAN_EVERY_MS` near the top sets the gap between scans (default 5000 ms). A full sweep takes about 3.5 seconds.
- The sketch keeps up to 64 access points per scan, 64 client devices and 40 log lines in memory. Restarting the board clears them.

## Troubleshooting

- **"Wi-Fi connect failed" in the Serial Monitor.** Check the SSID and password, and make sure the network has a 2.4 GHz band. If your router merges 2.4 and 5 GHz under one name, that usually works. A 5 GHz-only network won't.
- **Upload stalls or fails partway.** Set **Tools > Upload Speed** to **115200** and try again.
- **Serial Monitor shows garbage.** Set the baud rate to 115200.
- **Few or no client devices.** The ESP32 only hears 2.4 GHz traffic, and it mostly listens on your network's channel. Devices on 5 GHz won't show up, and phones send probe requests only now and then, so give it a few minutes.

## Use it responsibly

Stick to your own airspace. This tool shows the network names and hardware addresses of devices around you. Don't log, publish or share other people's device identifiers.
