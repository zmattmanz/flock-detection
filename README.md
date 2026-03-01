Flock-Detector 2.0: XIAO-Powered Surveillance Sniffer
An advanced WiFi and BLE (Bluetooth Low Energy) scanning tool built on the Seeed Studio XIAO ESP32-S3. This project identifies and logs surveillance hardware (like Flock Safety cameras and Raven GPS trackers) in real-time with localized GPS and Time data.

🚀 Features
Dual-Band Scanning: Simultaneous monitoring of 2.4GHz WiFi channels and BLE advertisements.

Expansion Board Integration: Full support for the XIAO Expansion Base OLED, Buzzer, and MicroSD card.

Targeted Detection: Uses custom MAC OUI prefixes and SSID patterns to identify specific hardware.

Real-Time Live Feed: A dedicated screen for monitoring all nearby signal activity (not just targets).

Geospatial Logging: Saves detections to datalog.csv with GPS coordinates and timestamps.

Session Statistics: Tracks "Lifetime" vs. "Session" detections across power cycles.

🛠 Hardware List
Microcontroller: Seeed Studio XIAO ESP32-S3

Baseboard: Seeed Studio Expansion Board for XIAO

Antenna: 2.4GHz Rod Antenna (2.81dBi)

GPS Module: NEO-6MV2 (Connected via 4-pin Female Jumper to Grove conversion cable)

Enclosure: ABS Waterproof Case with integrated cable glands.

📦 Required Libraries
Ensure you have the following installed in your Arduino IDE Library Manager:

NimBLE-Arduino (by h2zero)

ArduinoJson (by Benoit Blanchon)

Adafruit SSD1306 & Adafruit GFX

TinyGPS++ (by Mikal Hart) - Required for NEO-6M Support

RTClib (by Adafruit) - Required for Expansion Board Clock

⚙️ Installation
Install the esp32 board package in Arduino IDE.

Select Board: Select Seeed Studio XIAO ESP32S3.

Flash the FlockDetection.ino file.

Use the User Button (D1) on the expansion board to cycle through the 4 display screens.

🤝 Credits & Inspiration
This project is a modular evolution built upon the research and code of:

Colonel Panic / flock-you - For the original logic and MAC/SSID identification research.

f1yaw4y / FlockSquawk - The primary inspiration for the UI and field-ready implementation.
