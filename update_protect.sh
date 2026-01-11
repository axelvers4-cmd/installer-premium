#!/bin/bash
# This script replaces all occurrences of Malzxyz with Schnuffelll in the Pterodactyl panel files and adds a shield icon to the Active label.

# Replace case-sensitive variations
find /var/www/pterodactyl -type f -exec sed -i 's/Malzxyz/YudaMods/g' {} \;
find /var/www/pterodactyl -type f -exec sed -i 's/MALZXYZ/YUDAMODS/g' {} \;
find /var/www/pterodactyl -type f -exec sed -i 's/malzxyz/yudamods/g' {} \;

# Add shield icon to Active status in server list
sed -i 's/Active/Active 🛡️/g' /var/www/pterodactyl/resources/views/admin/servers/index.blade.php

echo "Branding updated to Schnuffelll and shield icon added."
