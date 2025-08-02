🛠 Installation Guide for ghost_hammer.cpp
1️⃣ System Requirements
``
    OS: Kali Linux / Parrot OS / Any Debian-based Linux
`
    Privileges: Root (needed for raw sockets)
`
    Packages:
`
        g++ (C++ compiler)

        make (optional)
`
        libpcap-dev (if required in future versions)

2️⃣ Clone the Repository
```
git clone https://github.com/cyberghosts03/ghost_hammer.git
cd ghost_hammer
```
3️⃣ Compile the Program
```
g++ -o ghost_hammer ghost_hammer.cpp -pthread
```
    -pthread is for multi-threading support.

4️⃣ Set Your Allowed Targets
`
    Open the allowed_targets.txt file:
```
nano allowed_targets.txt
```
Add only authorized IP addresses or domains you want to test, one per line:

    127.0.0.1
    mylabserver.local
    192.168.0.105

    Save & Exit: CTRL+O, ENTER, CTRL+X

5️⃣ Run the Program
```
sudo ./ghost_hammer
```
    sudo is needed because raw sockets require root permissions.

    Choose attack method from menu.

    Enter a target from your allowed_targets.txt file.

    Provide port, duration, and number of threads.

6️⃣ Stop the Program

    Press CTRL+C at any time to stop the running test.

⚠️ Disclaimer

    This tool must only be used for authorized testing on networks/systems you own or have written permission to test.
    Misuse of this tool for unauthorized attacks is illegal.
