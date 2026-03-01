# Flock-Detector 2.0: XIAO-Powered Surveillance Sniffer

An advanced WiFi and BLE (Bluetooth Low Energy) scanning tool built on the **Seeed Studio XIAO ESP32-S3**. Identifies and logs surveillance hardware — including **Flock Safety ALPR cameras**, **Raven gunshot detectors** (SoundThinking/ShotSpotter), and related monitoring devices — in real time with GPS-tagged CSV logs for use in FOIA requests, privacy auditing, and community mapping via [deflock.me](https://deflock.me).

---

## Features

- **Dual-Band Scanning** — Simultaneous WiFi promiscuous monitoring (2.4 GHz, channels 1–13) and BLE advertisement scanning via ESP32 coexistence, pinned to separate CPU cores for zero contention.
- **Multi-Method Detection** — MAC OUI prefix matching, SSID pattern matching, BLE device name matching, BLE manufacturer company ID detection (0x09C8 / XUNTONG), and Raven service UUID fingerprinting.
- **Raven Firmware Fingerprinting** — Automatically classifies detected Raven devices as firmware 1.1.x (legacy), 1.2.x, or 1.3.x based on which BLE service UUIDs they advertise. Firmware version is logged for post-analysis.
- **Detection Method Tracking** — Every detection logs *which* heuristic triggered the match (`mac_prefix`, `ssid_pattern`, `ble_name`, `mfg_id_0x09C8`, `raven_service_uuid`), enabling false-positive analysis and signature tuning.
- **Geospatial CSV Logging** — Saves detections to auto-numbered `FlockLog_XXX.csv` on MicroSD with GPS coordinates, altitude, speed, heading, timestamps, RSSI, and full device metadata.
- **7 OLED Display Screens** — Scanner status, detection stats (Flock WiFi / Flock BLE / Raven), last capture detail, live signal feed, GPS coordinates, activity bar chart, and signal proximity indicator.
- **Stealth Mode** — Long-press the button to kill the display and buzzer while scanning continues silently.
- **Expansion Board Integration** — Full support for the XIAO Expansion Base: OLED, buzzer, MicroSD card slot, and user button.

---

## Hardware

| Component | Part | Notes |
|-----------|------|-------|
| Microcontroller | [Seeed Studio XIAO ESP32-S3](https://www.seeedstudio.com/XIAO-ESP32S3-p-5627.html) | Dual-core 240 MHz, WiFi + BLE 5.0 |
| Baseboard | [Seeed Studio Expansion Board for XIAO](https://www.seeedstudio.com/Seeeduino-XIAO-Expansion-board-p-4746.html) | OLED (SSD1306 128×64), buzzer, MicroSD, button, battery connector |
| Antenna | 2.4 GHz Rod Antenna (2.81 dBi) | SMA or U.FL depending on your S3 variant |
| GPS Module | NEO-6MV2 | Connected via Grove-to-jumper cable (4-pin female) to the expansion board's Grove UART port |
| Enclosure | ABS Waterproof Case | With cable glands for antenna and USB-C power |
| Storage | MicroSD card (FAT32) | Any size; logs are small CSV files |

### Wiring

The expansion board handles most connections. The GPS module connects to the Grove UART port:

| GPS Pin | XIAO Pin | Function |
|---------|----------|----------|
| TX | D7 (RX) | GPS NMEA data to ESP32 |
| RX | D6 (TX) | Not used but connected |
| VCC | 3V3 | Power |
| GND | GND | Ground |

---

## Detection Methodology

Detection signatures are derived from field data collected by the surveillance detection community, including datasets from [deflock.me](https://deflock.me), [GainSec](https://github.com/GainSec) Raven research, and Will Greenberg's manufacturer ID work.

### WiFi (Promiscuous Mode)

Captures 802.11 management frames (beacons and probe requests) across all 13 channels with 500 ms hop intervals. Matches against:

- **SSID patterns** — `flock`, `FS Ext Battery`, `Penguin`, `Pigvision`, `FlockOS`, `flocksafety`, `FS_`
- **MAC OUI prefixes** — 23 known prefixes associated with Flock Safety hardware and their modem vendors (Cradlepoint, Murata, Liteon, Espressif)

### BLE (NimBLE Active Scan)

Scans BLE advertisements every 5 seconds with 100 ms intervals. Matches against:

- **Device name patterns** — `FS Ext Battery`, `Penguin`, `Flock`, `Pigvision`, `FlockCam`, `FS-`
- **MAC OUI prefixes** — Same prefix database as WiFi
- **Manufacturer company ID** — `0x09C8` (XUNTONG), associated with Flock Safety BLE hardware
- **Raven service UUIDs** — 8 known BLE service UUIDs across firmware versions 1.1.x through 1.3.x:

| UUID Prefix | Service | Firmware |
|-------------|---------|----------|
| `0x180A` | Device Information | All |
| `0x3100` | GPS Location | 1.2.x+ |
| `0x3200` | Power Management (battery/solar) | 1.2.x+ |
| `0x3300` | Network Status (LTE/WiFi) | 1.2.x+ |
| `0x3400` | Upload Statistics | 1.3.x |
| `0x3500` | Error/Failure Diagnostics | 1.3.x |
| `0x1809` | Health Thermometer (legacy) | 1.1.x |
| `0x1819` | Location and Navigation (legacy) | 1.1.x |

---

## Installation

### Prerequisites

- Arduino IDE with the **esp32** board package installed
- Board selection: **Seeed Studio XIAO ESP32S3**

### Required Libraries

Install via Arduino IDE Library Manager:

| Library | Author | Purpose |
|---------|--------|---------|
| NimBLE-Arduino | h2zero | BLE scanning |
| ArduinoJson | Benoit Blanchon | (available for future JSON export) |
| Adafruit SSD1306 | Adafruit | OLED display |
| Adafruit GFX | Adafruit | Graphics primitives |
| TinyGPS++ | Mikal Hart | GPS NMEA parsing |

### Flash

1. Connect the XIAO ESP32-S3 via USB-C.
2. Select **Seeed Studio XIAO ESP32S3** as the board.
3. Flash `FlockDetection.ino`.
4. Insert a FAT32-formatted MicroSD card.
5. Power on — listen for the two-tone boot beep (low → high).

---

## Usage

### Button Controls

| Action | Function |
|--------|----------|
| Short press (< 1 sec) | Cycle to next display screen |
| Long press (> 1 sec) | Toggle stealth mode (display + buzzer off) |

### Display Screens

| # | Screen | Description |
|---|--------|-------------|
| 0 | Scanner | Live scan status, current channel, uptime, animated sweep |
| 1 | Stats | Detection counts: Flock WiFi / Flock BLE / Raven (session + lifetime) |
| 2 | Last Capture | Most recent detection: type, MAC, RSSI, detection method |
| 3 | Live Feed | Rolling log of all nearby signals (detections highlighted) |
| 4 | GPS | Coordinates, speed, heading, satellite count, signal status |
| 5 | Activity Chart | Bar chart of detections per second over the last 25 seconds |
| 6 | Proximity | Visual RSSI bar for signal-strength-based device locating |

### Alerts

When a Flock or Raven device is detected:
- Buzzer sounds 3 rapid high-pitched beeps
- Display inverts briefly
- 60-second cooldown before the next alarm (prevents continuous beeping while driving past a cluster)

### CSV Log Format

Logs are saved to `/FlockLog_XXX.csv` on the MicroSD card with auto-incrementing filenames. Columns:

```
Uptime_ms, Date_Time, Channel, Capture_Type, Protocol, RSSI, MAC_Address,
Device_Name, TX_Power, Detection_Method, Extra_Data, Latitude, Longitude,
Speed_MPH, Heading_Deg, Altitude_M
```

`Capture_Type` is one of: `FLOCK_WIFI`, `FLOCK_BLE`, `RAVEN_BLE`

---

## Architecture

The firmware uses both cores of the ESP32-S3:

- **Core 0** — Dedicated scanner task: WiFi channel hopping and BLE scan scheduling
- **Core 1** — Main loop: GPS parsing, OLED rendering, button handling, SD card flushing, alarm output

A FreeRTOS mutex protects all shared state (detection counters, log buffers, display data) between cores. SD writes are buffered and flushed either every 10 seconds or when the buffer reaches 10 entries, whichever comes first.

---

## Credits & Acknowledgments

This project builds on the work of the surveillance detection community:

- **[Colonel Panic / flock-you](https://github.com/colonelpanichacks/flock-you)** — Original detection logic, MAC/SSID identification research, and the OUI-SPY hardware platform. Available at [colonelpanic.tech](https://colonelpanic.tech).
- **[f1yaw4y / FlockSquawk](https://github.com/f1yaw4y/FlockSquawk)** — Primary inspiration for the UI and field-ready implementation.
- **[Will Greenberg (@wgreenberg)](https://github.com/wgreenberg)** — BLE manufacturer company ID detection method (0x09C8 / XUNTONG).
- **[GainSec](https://github.com/GainSec)** — Raven BLE service UUID dataset (`raven_configurations.json`) enabling detection of SoundThinking/ShotSpotter acoustic surveillance devices across firmware versions 1.1.7, 1.2.0, and 1.3.1.
- **[DeFlock (FoggedLens/deflock)](https://github.com/FoggedLens/deflock)** — Crowdsourced ALPR location data and detection methodologies. Visit [deflock.me](https://deflock.me) to contribute sightings.

---

## Legal

This tool is intended for security research, privacy auditing, FOIA documentation, and educational purposes. Detecting the presence of surveillance hardware in public spaces is legal in most jurisdictions. Always comply with local laws regarding wireless scanning and signal interception.

---

## License

MIT
