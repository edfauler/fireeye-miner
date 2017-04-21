# fireeye-miner
MineMeld Miner for Fireeye's urllist implemented as an extension.

## How it works

This simple Miner periodically checks the FireEye urllist.txt also known as FireEye/Bluecoat Integration for new malicious and/or callback URLs and
extract those.


## PreConfiguration using a single FireEye NX

If there is only a standalone FireEye NX open the Fireeye CLI and enter the following commands:

```
 FireEye-NX > ena
 FireEye-NX # conf t
 FireEye-NX(config) # swg scan enable
 FireEye-NX(config) # swg scan period callback-url past 168 hours
 FireEye-NX(config) # swg scan period malicious-url past 24 hours
 FireEye-NX(config) # wr mem
 Saving configuration file ... Done!
 FireEye-NX(config) #
```
After SWG scan is enabled check if http://<FQDN of your Fireeye NX/urllist.txt is available.

## PreConfiguration using FireEye CMS

In case there a multiple FireEye NX appliances. Enable SWG scan as explained above on every Fireeye NX and then perform the same steps on the CMS as well.

```
 FireEye-CMS > ena
 FireEye-CMS # conf t
 FireEye-CMS(config) # swg scan enable
 FireEye-CMS(config) # wr mem
 Saving configuration file ... Done!
 FireEye-CMS(config) #
```

After SWG scan is enabled check if http://<FQDN of your Fireeye CMS/urllist.txt is available

## Installation

You can install this extension directly from the git repo.
1. Logon to you Minemeld installation and browse to Setup -> Extension.
2. Click add a 'git' extension.
3. Copy & Paste the Repository URL and click on 'Retrieve'.
4. Choose "Master" and click "Install"
5. Enable the Extension
6. Browse to config and switch to prototypes
7. Search for fireeye and open the prototypes
8. Click "New" on the top right
9. Name your prototype and modify fireeye_fqdn with the FQDN of your Fireeye NX or CMS appliance
10. Browse back to Config and click on the "eye" symbol on the left bottom of the miner list
11. A "+" Sign appears on the right. Use it to create 3 miners.
12. First the "Miner". Choose a name like "myfireeye-miner" and select your protoype created in step 9 then click OK
13. Create the second miner the processor. Choose a name like "myfireeye-processor" and pick "stdlib.aggregatorURL" as Prototype
14. Now the last miner the "Output". Choose a name like "myfireeye-output" and pick e.g. "stdlib.feedHCGreen" as Prototype
15. Click "Commit" to safe your work.

To confirm if you new miner works browse to Nodes and search for "fireeye" open your "Miner" created in step 12 and see if indicators show up in the log
