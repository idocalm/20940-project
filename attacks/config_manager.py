import json
from pathlib import Path

class ServerConfigManager:
    """Manages server configuration for experiments"""
    
    def __init__(self, config_file="server/config.py"):
        self.config_file = Path(config_file)
        
    def update_config(self, **settings):
        """Updates the server configuration"""
        # Read the current file
        content = self.config_file.read_text()
        
        # Replace values in SETTINGS
        for key, value in settings.items():
            if isinstance(value, str):
                value_str = f'"{value}"'
            elif isinstance(value, bytes):
                value_str = f'b"{value.decode()}"' if value else 'b""'
            else:
                value_str = str(value)
            
            # Search and replace the line
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if f'"{key}":' in line:
                    indent = len(line) - len(line.lstrip())
                    lines[i] = ' ' * indent + f'"{key}": {value_str},'
            
            content = '\n'.join(lines)
        
        # Write the file
        self.config_file.write_text(content)
        print(f"⚙️  Configuration updated: {', '.join(settings.keys())}")
        
    def reset_to_defaults(self):
        """Resets all security settings to False"""
        self.update_config(
            pepper_enabled=False,
            captcha_enabled=False,
            lockout_enabled=False,
            rate_limit_enabled=False,
            totp_enabled=False
        )

