from privacyidea.app import create_app
import sys
sys.stdout = sys.stderr
# Now we can select the config file:
application = create_app(config_name="production",
                         config_file="/etc/privacyidea/pi.cfg")
