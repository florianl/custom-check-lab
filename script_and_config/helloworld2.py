# version 2.1 - special for Custom Check Lab
# Changes vs 2.0:
#  - Linux support: on Linux the agent runs as dd-agent (home /opt/datadog-agent,
#  #  which has no Desktop), so we look for the logged-in user's Desktop under
#  #  /home instead of using "~".
#  - Optional "desktop_path" instance setting in conf.yaml overrides all
#    auto-detection.
#  - Requires on macOS: FDA on /opt/datadog-agent/bin/agent/agent (TCC layer)
#    and an ACL on ~/Desktop for _dd-agent (POSIX layer, folders are mode 700
#    on accounts created on modern macOS):
#    chmod +a "user:_dd-agent allow list,search,readattr,readextattr,readsecurity" ~/Desktop
#  - Requires on Linux: dd-agent must be able to reach the Desktop, e.g.
#    home dirs are often mode 710/750, so:
#    sudo setfacl -m u:dd-agent:x /home/<user>

import glob
import os
import stat
import json
import time
import logging
import socket
import platform
import subprocess
from datadog_checks.base import AgentCheck

class Helloworld2Check(AgentCheck):
    def check(self, instance):
        # Resolve Desktop path based on OS
        desktop_path = instance.get('desktop_path')
        if not desktop_path:
            if platform.system().lower() == 'windows':
                desktop_path = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
            elif platform.system().lower() == 'darwin':
                # "~" would expand to _dd-agent's home (/var/empty), so ask macOS
                # who owns the console (= the logged-in GUI user) instead.
                try:
                    console_user = subprocess.check_output(
                        ["stat", "-f", "%Su", "/dev/console"], timeout=5
                    ).decode().strip()
                except Exception:
                    console_user = None
                if console_user and console_user not in ("root", ""):
                    desktop_path = f"/Users/{console_user}/Desktop"
                else:
                    desktop_path = os.path.expanduser("~/Desktop")  # fallback (e.g. login screen)
            else:
                # Linux: the agent's dd-agent user has no Desktop of its own
                # (/opt/datadog-agent). Look for human users' Desktops under /home.
                candidates = sorted(glob.glob('/home/*/Desktop'))
                if candidates:
                    desktop_path = candidates[0]
                    if len(candidates) > 1:
                        self.log.warning(
                            "Multiple Desktops found (%s); pass desktop_path in the instance config "
                            "to pick one", candidates)
                else:
                    # Empty glob can mean "no Desktop exists" OR "dd-agent cannot
                    # stat /home/* (home dirs are often 700/710 + an ACL whose mask
                    # has been zeroed by a later chmod)". Log it so the fallback
                    # below doesn't look like a mysterious bug.
                    desktop_path = os.path.expanduser("~/Desktop")
                    self.log.warning(
                        "No Desktop found under /home/*/Desktop; this is often a permission "
                        "issue for the agent user (check ACL mask on the home dirs). "
                        "Falling back to %s", desktop_path
                    )



        # Count visible files and folders
        try:
            def is_visible(name, full_path):
                if name.startswith('.'):
                    return False
                if not os.path.exists(full_path):
                    return False
                if platform.system().lower() != 'windows':
                    try:
                        # st_flags only exists on macOS/BSD, not on Linux
                        if getattr(os.stat(full_path), 'st_flags', 0) & stat.UF_HIDDEN:
                            return False
                    except OSError:
                        pass
                return True

            file_count = len([
                f for f in os.listdir(desktop_path)
                if is_visible(f, os.path.join(desktop_path, f))
            ])
        except Exception as e:
            self.log.warning(f"Could not access Desktop: {e}")
            file_count = -1

        # Submit metric only on success; report failures via a service check
        # so -1 doesn't pollute the gauge
        if file_count >= 0:
            self.gauge('helloworld2.desktop_file_count', file_count)
            self.service_check('helloworld2.can_read_desktop', AgentCheck.OK)
        else:
            self.service_check('helloworld2.can_read_desktop', AgentCheck.CRITICAL,
                               message=f"Could not access {desktop_path}")

        # Set log directory based on OS
        system = platform.system().lower()
        if system == 'windows':
            log_dir = os.environ.get("TEMP", "C:\\Temp")
        elif system == 'darwin':
            log_dir = '/opt/datadog-agent/logs'
        else:
            log_dir = '/var/log/datadog'

        log_file = os.path.join(log_dir, 'helloworld2.log')
        state_file = os.path.join(log_dir, 'helloworld2_state.json')
        host = socket.gethostname()

        # Set up logger
        logger = logging.getLogger('helloworld2')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            try:
                os.makedirs(log_dir, exist_ok=True)
                file_handler = logging.FileHandler(log_file, encoding='utf-8')
            except OSError as e:
                self.log.warning(f"Could not open log file {log_file}: {e}")
                return
            formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        # Load previous state
        last_count = None
        last_logged = 0
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
            last_count = state.get("last_count")
            last_logged = state.get("last_logged", 0)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        now = int(time.time())
        log_this_run = False

        # Decide whether to log
        if file_count != last_count:
            log_this_run = True
            log_reason = f"File count changed: {last_count} → {file_count} on {host}"
        elif now - last_logged > 43200:
            log_this_run = True
            log_reason = f"No change, but 12h passed since last log. {host} was alive."

        # Log using correct level and emoji
        if log_this_run:
            if file_count < 0:
                logger.error(f"❌ {log_reason} (Desktop not readable)")
            elif file_count > 18:
                logger.warning(f"⚠️ {log_reason}")
            else:
                logger.info(f"✅ {log_reason}")

            # Save new state
            try:
                with open(state_file, 'w') as f:
                    json.dump({
                        "last_count": file_count,
                        "last_logged": now
                    }, f)
            except Exception as e:
                self.log.warning(f"Could not write state file: {e}")
