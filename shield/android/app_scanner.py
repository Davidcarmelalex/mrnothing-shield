"""
Android App Scanner — Interfaces with ADB to extract
installed application data from Android devices.
"""

import subprocess
from typing import Dict, List, Optional


class AndroidAppScanner:
    """
    Handles Android device communication via ADB for
    extracting app information, permissions, and metadata.
    """

    def __init__(self, device_id: Optional[str] = None):
        self.device_id = device_id
        self.adb_path = self._find_adb()

    def _find_adb(self) -> str:
        """Locate ADB executable."""
        try:
            result = subprocess.run(["which", "adb"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return "adb"  # Assume in PATH

    def _adb_shell(self, command: str) -> str:
        """Execute ADB shell command."""
        device_flag = f"-s {self.device_id}" if self.device_id else ""
        full_command = f"{self.adb_path} {device_flag} shell {command}"
        
        try:
            result = subprocess.run(
                full_command.split(),
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout
        except Exception as e:
            return f"ERROR: {str(e)}"

    def get_installed_packages(self, include_system: bool = True) -> List[Dict]:
        """
        Get list of installed packages with metadata.
        
        Returns:
            List of dicts containing package_name, app_name, permissions, etc.
        """
        # List all packages
        flags = "-f -u" if include_system else "-3"
        output = self._adb_shell(f"pm list packages {flags}")
        
        packages = []
        for line in output.strip().split("\n"):
            if line.startswith("package:"):
                # Parse: package:/data/app/.../base.apk=com.example.app
                parts = line.replace("package:", "").split("=")
                if len(parts) == 2:
                    package_name = parts[1]
                    packages.append({
                        "package_name": package_name,
                        "apk_path": parts[0],
                        "permissions": self._get_package_permissions(package_name),
                        "app_name": self._get_app_label(package_name),
                    })
        
        return packages

    def _get_package_permissions(self, package_name: str) -> List[str]:
        """Get permissions for a specific package."""
        output = self._adb_shell(f"dumpsys package {package_name} | grep -A 1000 'requested permissions'")
        permissions = []
        for line in output.split("\n"):
            line = line.strip()
            if line.startswith("android.permission."):
                permissions.append(line)
        return permissions

    def _get_app_label(self, package_name: str) -> str:
        """Get human-readable app name."""
        output = self._adb_shell(
            f"pm dump {package_name} | grep 'applicationLabel'"
        )
        if "=" in output:
            return output.split("=")[-1].strip()
        return package_name

    def get_launcher_packages(self) -> List[str]:
        """
        Get packages that appear in the launcher.
        
        Returns:
            List of package names visible in launcher
        """
        output = self._adb_shell(
            "pm query-activities -a android.intent.action.MAIN "
            "-c android.intent.category.LAUNCHER 2>/dev/null"
        )
        
        packages = set()
        for line in output.split("\n"):
            if "packageName=" in line:
                pkg = line.split("packageName=")[-1].split(",")[0].strip()
                packages.add(pkg)
        
        return list(packages)

    def is_package_hidden(self, package_name: str) -> bool:
        """Check if a package is installed but hidden from launcher."""
        installed = self.get_installed_packages(include_system=True)
        launcher = self.get_launcher_packages()
        
        installed_names = {p["package_name"] for p in installed}
        
        if package_name not in installed_names:
            return False  # Not installed
        
        return package_name not in launcher

    def get_app_install_source(self, package_name: str) -> str:
        """Determine where an app was installed from."""
        output = self._adb_shell(f"dumpsys package {package_name} | grep 'installerPackageName'")
        if "=" in output:
            return output.split("=")[-1].strip()
        return "unknown"
