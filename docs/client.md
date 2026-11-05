# Client usage

There are several ways how to send information from the monitored machine to the Pakiti server. The Pakiti suite
contains a [client](https://github.com/CESNET/pakiti-client/) that can be deployed on the infrastructure. Environments
utilizing the [GLPI toolset](https://glpi-project.org/) can use the glpi tools to send reports to Pakiti too. Details
on the usage are below.

## Pakiti client
Run pakiti-client -h for help

    perl /var/www/pakiti3/bin/pakiti-client -h

##### send report via https
    perl /var/www/pakiti3/bin/pakiti-client --url="https://yourdomain.com/feed/"

##### Running kernel packages
Besides `kernel: <uname -r>` and the list of installed packages, newer clients send the header field

    running-kernel-pkgs: kernel-core 0:5.14.0-427.13.1.el9_4 x86_64;kernel-modules 0:5.14.0-427.13.1.el9_4 x86_64

listing the packages which own the running kernel (`/lib/modules/$(uname -r)` and `/boot/vmlinuz-$(uname -r)`).
The server uses it, together with matching the package versions against `uname -r`, to decide which kernel
packages are running. Kernel packages that are installed but not running are stored, but their CVEs are not
counted, tagged or notified. Older clients without this field keep working, the server then relies on
the version matching only.

## GLPI
GLPI is either in your linux distribution or install it according to https://github.com/glpi-project/glpi-agent/releases

#### Create inventory in json format and save to file
    glpi-inventory --json -t Tag > /tmp/glpi
#### Send created inventory to pakiti
    glpi-injector -f /tmp/glpi -u https://yourdomain.com/feed/
