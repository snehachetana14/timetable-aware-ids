#Timetable-Aware Intrusion Detection System
An SDN based IDS that uses a college timetable as the
baseline for normal network behaviour. Live traffic is compared
against the schedule, and anything that does not match is flagged and the device is blocked.

Status: in development. Environment working; detection logic in progress.

## Structure
- network/ Mininet topology and attack scripts
- controller/ Ryu controller , detection logic,timetable engine
- timetable/ the schedule file
- dashboard/ monitoring dashboard

##Setup
Requires Ubuntu , Mininet , Open vSwitch, and Python3.9.

python3.9 -m venv ryu-venv
source ryu-venv/bin/activate
pip install -r requirements.txt

##Team
-@snehachetana14 - controller, detection,timetable engine, dashboard
-@aishwanee - network topology, attack simulation

#Tools
Mininet , Ryu , Open Vswitch , OPenFlow , Python , nmap , hping3
