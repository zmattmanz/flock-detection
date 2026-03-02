# Flock-Detector 3.0: XIAO-Powered Surveillance Sniffer

An advanced WiFi and BLE (Bluetooth Low Energy) scanning tool built on the **Seeed Studio XIAO ESP32-S3**. Identifies and logs surveillance hardware — including **Flock Safety ALPR cameras**, **Raven gunshot detectors** (SoundThinking/ShotSpotter), and related monitoring devices — in real time with GPS-tagged CSV logs for use in FOIA requests, privacy auditing, and community mapping via [deflock.me](https://deflock.me).

---

## What's New in v3.0

- **Alarm Escalation** — Sound pattern varies by confidence: 1 beep for MEDIUM, 3 beeps for HIGH, 5 rapid beeps for CERTAIN. Know whether to pull over from sound alone.
- **Session Persistence** — Lifetime detection counters and uptime survive power cycles via LittleFS flash storage. Saves every 60 seconds, restores on boot.
- **Time-Windowed Re-Detection** — Same MAC address re-logs after 5 minutes with fresh GPS coordinates, enabling multi-pass confirmation of fixed installations.
- **Adaptive Channel Dwell** — 500 ms on channels 1, 6, 11 (non-overlapping, where Flock cameras most likely operate), 200 ms on all others.
- **RSSI Trend Tracking** — Tracks signal strength over time for detected devices. A rise-peak-fall pattern (characteristic of driving past a fixed installation) earns a confidence bonus. Devices that appear suddenly at close range (phones, passing cars) do not.
- **WiFi SSID Format Validation** — The specific `Flock-XXXX` hex format (where XXXX is a partial MAC address) scores higher than a generic "flock" substring match, reducing false positives from similarly-named consumer networks.
- **BLE Address Type Checking** — Public and random static BLE addresses (used by Flock batteries) earn a confidence bonus. Random resolvable addresses (phones rotating every ~15 minutes) do not.

---

## Features

- **Dual-Band Scanning** — Simultaneous WiFi promiscuous monitoring (2.4 GHz, channels 1–13) and BLE advertisement scanning via ESP32 coexistence, pinned to separate CPU cores for zero contention.
- **Multi-Method Confidence Scoring** — Each detection method contributes weighted points to a confidence score (0–100%). Multiple corroborating signals stack. Alarm triggers at 40% threshold. Scores are logged to CSV and displayed on OLED as MEDIUM / HIGH / CERTAIN.
- **Detection Methods** — MAC OUI prefix matching (40 pts), SSID pattern matching (50 pts), SSID format validation (65 pts), BLE device name matching (45 pts), manufacturer company ID detection (60 pts, 0x09C8 / XUNTONG), TN serial number extraction (80 pts), Raven service UUID fingerprinting (70–90 pts), BLE address type analysis (+10 pts), RSSI trend analysis (+15 pts), multi-method corroboration bonus (+20 pts).
- **Raven Firmware Fingerprinting** — Automatically classifies detected Raven devices as firmware 1.1.x (legacy), 1.2.x, or 1.3.x based on which BLE service UUIDs they advertise. Firmware version is logged for post-analysis.
- **Detection Method Tracking** — Every detection logs *which* heuristics triggered the match (`mac_prefix`, `ssid_pattern`, `ssid_fmt`, `ble_name`, `mfg_id_0x09C8`, `tn_serial`, `penguin_num`, `raven_service_uuid`, `static_addr`, `pub_addr`), enabling false-positive analysis and signature tuning.
- **Geospatial CSV Logging** — Saves detections to auto-numbered `FlockLog_XXX.csv` on MicroSD with GPS coordinates, altitude, speed, heading, timestamps, RSSI, confidence scores, and full device metadata.
- **7 OLED Display Screens** — Scanner status (with primary channel indicator), detection stats (Flock WiFi / Flock BLE / Raven, session + lifetime), last capture detail with confidence, live signal feed, GPS coordinates, activity bar chart, and signal proximity indicator.
- **Stealth Mode** — Long-press the button to kill the display and buzzer while scanning continues silently.
- **Session Persistence** — Lifetime counters stored in flash via LittleFS. Stats survive power cycles and accumulate across sessions.
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

Detection signatures are derived from field data collected by the surveillance detection community, including datasets from [deflock.me](https://deflock.me), [GainSec](https://github.com/GainSec) Raven research, Will Greenberg's manufacturer ID work, and the FlockBack project.

### Confidence Scoring

Each detection method contributes weighted points to a cumulative confidence score. Multiple independent methods corroborating the same device stack their scores. The alarm triggers at 40 points (MEDIUM), with labels assigned at 70 (HIGH) and 85 (CERTAIN).

| Method | Points | Example |
|--------|--------|---------|
| MAC OUI prefix | 40 | Known Flock/Murata/LiteOn prefix |
| SSID pattern (generic) | 50 | Contains "flock", "Penguin", etc. |
| SSID format (specific) | 65 | Matches `Flock-XXXX` hex format |
| BLE device name | 45 | "FS Ext Battery", "FlockCam", etc. |
| Manufacturer ID (0x09C8) | 60 | XUNTONG company ID in BLE mfg data |
| Raven UUID (single) | 70 | One known Raven service UUID |
| Raven UUID (3+) | 90 | Multiple Raven UUIDs from one device |
| TN serial in mfg data | 80 | Pattern like TN72023022000771 |
| Penguin numeric name | 15 | 10-digit decimal (post-March 2025 FW) |
| **Bonuses** | | |
| Strong RSSI (> -50 dBm) | +10 | Device is very close |
| Multi-method (2+ signals) | +20 | Independent methods corroborate |
| BLE static/public address | +10 | Consistent address, not rotating |
| Stationary RF signature | +15 | RSSI rise-peak-fall pattern |

**Example:** A random Murata BLE module (08:3a:88 OUI) scores 40 points (MEDIUM). A real Flock battery with the same OUI + XUNTONG manufacturer ID + "FS Ext Battery" name + static address + stationary signature scores 40 + 60 + 45 + 10 + 15 + 20 = 100 (CERTAIN).

### WiFi (Promiscuous Mode)

Captures 802.11 management frames (beacons and probe requests) across all 13 channels with adaptive dwell times (500 ms on channels 1/6/11, 200 ms on others). A hardware filter (`WIFI_PROMIS_FILTER_MASK_MGMT`) ensures only management frames reach the callback, reducing CPU load by 10–50× in busy RF environments. Matches against:

- **SSID patterns** — `flock`, `FS Ext Battery`, `Penguin`, `Pigvision`, `FlockOS`, `flocksafety`, `FS_`
- **SSID format** — Specific `Flock-XXXX` hex format validation (higher confidence than generic match)
- **MAC OUI prefixes** — 24 known prefixes associated with Flock Safety hardware and their modem/module vendors (Cradlepoint, Murata, LiteOn, Espressif, Sierra Wireless)

### BLE (NimBLE Active Scan)

Scans BLE advertisements every 3 seconds with 2-second duration and 97 ms interval/window (prime number reduces aliasing with common BLE advertisement intervals). Duplicate suppression is enabled within scan cycles. Matches against:

- **Device name patterns** — `FS Ext Battery`, `Penguin`, `Flock`, `Pigvision`, `FlockCam`, `FS-`
- **Penguin numeric names** — 10-digit decimal strings (post-March 2025 firmware dropped the "Penguin-" prefix)
- **MAC OUI prefixes** — Same prefix database as WiFi (24 entries)
- **Manufacturer company ID** — `0x09C8` (XUNTONG), associated with Flock Safety BLE hardware
- **TN serial numbers** — ASCII "TN" pattern in XUNTONG manufacturer data payload (e.g., TN72023022000771)
- **BLE address type** — Public and random static addresses (Flock batteries) vs. random resolvable (phones)
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

### RSSI Trend Tracking

When a device crosses the alarm threshold, the firmware begins tracking its RSSI over multiple observations (up to 5 samples over 15 seconds). A fixed installation produces a characteristic rise-peak-fall curve as you drive past — signal gets stronger as you approach, peaks, then fades. A phone in someone's pocket or a device in a passing car appears suddenly at close range and disappears just as fast. Devices exhibiting the stationary pattern receive a +15 confidence bonus. Each device is only scored once to prevent inflation.

---

## Installation

### Prerequisites

- Arduino IDE with the **esp32** board package installed
- Board selection: **Seeed Studio XIAO ESP32S3**
- **Partition scheme**: Select a partition scheme with LittleFS support (e.g., "Default 4MB with spiffs" works — LittleFS uses the same partition)

### Required Libraries

Install via Arduino IDE Library Manager:

| Library | Author | Purpose |
|---------|--------|---------|
| NimBLE-Arduino | h2zero | BLE scanning |
| ArduinoJson | Benoit Blanchon | (available for future JSON export) |
| Adafruit SSD1306 | Adafruit | OLED display |
| Adafruit GFX | Adafruit | Graphics primitives |
| TinyGPS++ | Mikal Hart | GPS NMEA parsing |

LittleFS is included in the ESP32 Arduino core and does not require separate installation.

### Flash

1. Connect the XIAO ESP32-S3 via USB-C.
2. Select **Seeed Studio XIAO ESP32S3** as the board.
3. Flash `FlockDetection_v3.0.ino`.
4. Insert a FAT32-formatted MicroSD card.
5. Power on — listen for the two-tone boot beep (low → high).
6. Check serial output for restored session data (if any previous sessions exist).

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
| 0 | Scanner | Live scan status, current channel (* on primary channels), uptime, animated sweep |
| 1 | Stats | Detection counts: Flock WiFi / Flock BLE / Raven (session + lifetime), total uptime |
| 2 | Last Capture | Most recent detection: type, MAC, RSSI, confidence score + label |
| 3 | Live Feed | Rolling log of all nearby signals (detections highlighted with confidence %) |
| 4 | GPS | Coordinates, speed, heading, satellite count, signal status |
| 5 | Activity Chart | Bar chart of detections per second over the last 25 seconds |
| 6 | Proximity | Visual RSSI bar with qualitative distance labels and confidence % |

### Alarm Escalation

The alarm sound pattern varies by confidence level so you can assess detections by ear while driving:

| Confidence | Beeps | Frequency | Meaning |
|------------|-------|-----------|---------|
| MEDIUM (40–69%) | 1 short | 1000 Hz | Something might be here |
| HIGH (70–84%) | 3 beeps | 1200 Hz | Likely detection |
| CERTAIN (85–100%) | 5 rapid | 1500 Hz | Confirmed device |

The 60-second cooldown between alarms prevents continuous beeping while driving past a cluster of devices.

### CSV Log Format

Logs are saved to `/FlockLog_XXX.csv` on the MicroSD card with auto-incrementing filenames. Columns:

```
Uptime_ms, Date_Time, Channel, Capture_Type, Protocol, RSSI, MAC_Address,
Device_Name, TX_Power, Detection_Method, Confidence, Confidence_Label,
Extra_Data, Latitude, Longitude, Speed_MPH, Heading_Deg, Altitude_M
```

`Capture_Type` is one of: `FLOCK_WIFI`, `FLOCK_BLE`, `RAVEN_BLE`

`Detection_Method` contains space-separated tags indicating which heuristics triggered (e.g., `mac mfg_0x09C8 name static_addr`).

`Confidence` is the numeric score (0–100) and `Confidence_Label` is MEDIUM, HIGH, or CERTAIN.

### Session Persistence

Lifetime counters are stored in LittleFS flash at `/flock_session.dat` and saved every 60 seconds. On boot, the firmware restores previous lifetime stats and prints them to serial:

```
Restored: WiFi=47 BLE=23 Time=02:34:15 Total=70
```

To reset lifetime stats, erase the flash partition or delete the file via serial/code.

### Time-Windowed Re-Detection

The MAC deduplication ring buffer (200 entries) now timestamps each entry. If the same MAC is seen again after 5 minutes, it is re-logged with fresh GPS coordinates. This enables:

- Confirming fixed installations from multiple passes on different streets
- Building stronger FOIA evidence ("detected at this location on 3 separate passes over 20 minutes")
- Distinguishing fixed cameras from mobile units on tow-behind trailers

---

## Architecture

The firmware uses both cores of the ESP32-S3:

- **Core 0** — Dedicated scanner task: WiFi channel hopping (adaptive dwell) and BLE scan scheduling
- **Core 1** — Main loop: GPS parsing, OLED rendering, button handling, SD card flushing, alarm output, session persistence, RSSI tracker expiry

A FreeRTOS mutex protects all shared state (detection counters, log buffers, display data) between cores. SD writes are buffered and flushed either every 10 seconds or when the buffer reaches 10 entries, whichever comes first.

### Memory Budget

| Structure | Size | Notes |
|-----------|------|-------|
| MAC ring buffer | 200 entries | Time-stamped, 5-min re-detection window |
| RSSI tracker | 16 devices × 5 samples | 15-second expiry, scored once per device |
| SD write buffer | 10 entries | Flushed to card on timer or count |
| LittleFS session | ~64 bytes | 4 counters saved to flash |

---

## Credits & Acknowledgments

This project builds on the work of the surveillance detection community:

- **[Colonel Panic / flock-you](https://github.com/colonelpanichacks/flock-you)** — Original detection logic, MAC/SSID identification research, and the OUI-SPY hardware platform. Available at [colonelpanic.tech](https://colonelpanic.tech).
- **[f1yaw4y / FlockSquawk](https://github.com/f1yaw4y/FlockSquawk)** — Primary inspiration for the UI and field-ready implementation.
- **[Will Greenberg (@wgreenberg)](https://github.com/wgreenberg)** — BLE manufacturer company ID detection method (0x09C8 / XUNTONG).
- **[GainSec](https://github.com/GainSec)** — Raven BLE service UUID dataset (`raven_configurations.json`) enabling detection of SoundThinking/ShotSpotter acoustic surveillance devices across firmware versions 1.1.7, 1.2.0, and 1.3.1. Also documented the `Flock-XXXX` SSID format and March 2025 Penguin firmware changes.
- **[DeFlock (FoggedLens/deflock)](https://github.com/FoggedLens/deflock)** — Crowdsourced ALPR location data and detection methodologies. Visit [deflock.me](https://deflock.me) to contribute sightings.
- **[FlockBack](https://github.com/FlockBack)** — Community detection data contributions.

---

## Legal

This tool is intended for security research, privacy auditing, FOIA documentation, and educational purposes. Detecting the presence of surveillance hardware in public spaces is legal in most jurisdictions. Always comply with local laws regarding wireless scanning and signal interception.

---

## License

MIT
