# AutoNessusReborn
AutoNessusReborn communicates with the Nessus API to help with automating scans. You can list all scans, list all policies, start, stop, pause, and resume a scan. It is recommended to create a cron job for automating the start or pause of scans if a specific testing window is desired.

AutoNessusReborn is based on the original [AutoNessus](https://github.com/deepseasred/AutoNessus) script but has been completely rewritten to use Python3.

## Installation
```
git clone https://github.com/markjhunsinger/AutoNessusReborn.git
cd AutoNessusReborn
chmod +x autonessus2.py
```
Edit the `autonessus.conf` file with your Nessus details.

## Usage
`python autoNessus.py -h`

## Examples
List all scans and scan IDs (scan IDs to be used with other flags):

`./autonessus2.py --list`

Start scan 42:

`./autonessus2.py --start 42`

Pause scan 42:

`./autonessus2.py --pause 42`

## Credits
Thank you to Matt Grandy for creating the original [AutoNessus](https://github.com/deepseasred/AutoNessus) script for which this rebirth is based on.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
