import logging
from typing import Tuple, List, Optional
from rich.text import Text
from textual.app import ComposeResult
from textual.widgets import Static, Header, Footer
from textual.screen import Screen
from textual.containers import Container
from textual.binding import Binding

# Configure logger for map UI
logger = logging.getLogger("ui_map")

# Raw ASCII Map Template (approx. 77 columns wide, 24 rows high)
MAP_TEXT = r"""          . _..::__:  ,-"-"._       |]       ,     _,.__              
  _.___ _ _<_>`!(._`.`-.    /        _._     `_ ,_/  '  '-._.---.-.__ 
.{     " " `-==,',._\{  \  / {)     / _ ">_,-' `                 /-/_ 
 \_.:--.       `._ )`^-. "'      , [_/(                       __,/-'  
'"'     \         "    _L       |-_,--'                )     /. (|    
         |           ,'         _)_.\\._<> {}              _,' /  '   
         `.         /          [_/_'` `"(                <'}  )       
          \\    .-. )          /   `-'"..' `:._          _)  '        
   `        \  (  `(          /         `:\  > \  ,-^.  /' '          
             `._,   ""        |           \`'   \|   ?_)  {\          
                `=.---.       `._._       ,'     "`  |' ,- '.         
                  |    `-._        |     /          `:`<_|=--._       
                  (        >       .     | ,          `=.__.`-'\      
                   `.     /        |     |{|              ,-.,\     . 
                    `.   /          \   / `'            ,"     \      
                    |   ,'          \   / `'            ,"     \      
                    |  /             |_'                |  __  /      
                    | |                                 '-'  `-'   \. 
                    |/                                        "    /  
                    \.                                            '   
                                                                      
                     ,/           ______._.--._ _..---.---------.     
__,-----"-..?----_/ )\    . ,-'"             "                  (__--/
                      /__/\/                                          """

# Split and pad the lines to form a perfect grid
MAP_LINES = [line.rstrip() for line in MAP_TEXT.splitlines()]
MAP_WIDTH = max(len(line) for line in MAP_LINES)
MAP_GRID = [line.ljust(MAP_WIDTH) for line in MAP_LINES]
MAP_HEIGHT = len(MAP_GRID)

def project_coords(lat: float, lon: float, width: int, height: int) -> Tuple[int, int]:
    """
    Projects latitude and longitude onto a grid of width x height.
    Uses Equirectangular (Plate Carrée) projection mapping:
    - Longitude: -180 to +180 -> 0 to width-1
    - Latitude: +90 to -90 -> 0 to height-1
    """
    x = int((lon + 180.0) * (width / 360.0))
    y = int((90.0 - lat) * (height / 180.0))
    return max(0, min(width - 1, x)), max(0, min(height - 1, y))

class WorldMapWidget(Static):
    """
    Textual widget displaying an ASCII world map with origin and destination points.
    All data is read directly from the main application state to ensure consistency.
    """
    
    def on_mount(self) -> None:
        # Periodic update to make malicious points blink and pick up new connections
        self.set_interval(1.0, self.refresh)

    def render(self) -> Text:
        app = self.app
        # Retrieve origin coordinates
        origin = getattr(app, "origin_coords", None)
        # Retrieve geolocation dictionary (ip -> (lat, lon))
        geo_data = getattr(app, "geo_data", {})
        # Retrieve set of malicious IPs
        malicious_ips = getattr(app, "malicious_ips", set())
        # Retrieve active connections grouped by process
        grouped_data = getattr(app, "grouped_data", {})
        
        # Get distinct geolocated destination coordinates
        clean_destinations = []
        malicious_destinations = []
        seen_ips = set()
        
        for proc_key, ports_dict in grouped_data.items():
            for port, conns in ports_dict.items():
                for conn in conns:
                    ip = conn.get("remote_ip", "")
                    if ip and ip != "*" and ip in geo_data:
                        if ip not in seen_ips:
                            seen_ips.add(ip)
                            lat, lon = geo_data[ip]
                            if ip in malicious_ips:
                                malicious_destinations.append((lat, lon, ip))
                            else:
                                clean_destinations.append((lat, lon, ip))
                                
        # Create a deep copy of the map grid to modify
        grid = [list(row) for row in MAP_GRID]
        
        # Color code the background map in a dim, cyber-esque palette
        # Using a sleek dark theme: map outline in a deep blue/gray (#2e3440 or #3b4252)
        styles = [["#3b4252" for _ in range(MAP_WIDTH)] for _ in range(MAP_HEIGHT)]
        
        # Overlay clean destinations (Neon Green dots)
        for lat, lon, ip in clean_destinations:
            x, y = project_coords(lat, lon, MAP_WIDTH, MAP_HEIGHT)
            grid[y][x] = "•"
            styles[y][x] = "bold #00FF66" # Neon green accent
            
        # Overlay malicious destinations (Red skulls/crossbones or bold blinking dots)
        for lat, lon, ip in malicious_destinations:
            x, y = project_coords(lat, lon, MAP_WIDTH, MAP_HEIGHT)
            grid[y][x] = "☠"
            styles[y][x] = "bold #FF3333 blink" # Blinking bright red
            
        # Overlay origin (Cyan star)
        if origin:
            olat, olon = origin
            ox, oy = project_coords(olat, olon, MAP_WIDTH, MAP_HEIGHT)
            grid[oy][ox] = "★"
            styles[oy][ox] = "bold #00E5FF" # Neon Cyan origin
            
        # Build the final Rich Text object
        text = Text()
        for y in range(MAP_HEIGHT):
            for x in range(MAP_WIDTH):
                text.append(grid[y][x], style=styles[y][x])
            text.append("\n")
            
        # Append legend at the bottom
        text.append("\n", style="")
        text.append(" Legend:  ", style="bold #e2e8f0")
        text.append("★", style="bold #00E5FF")
        text.append(" Origin (You)   ", style="#a0aec0")
        text.append("•", style="bold #00FF66")
        text.append(" Active Destination   ", style="#a0aec0")
        text.append("☠", style="bold #FF3333 blink")
        text.append(" Malicious Host\n", style="#a0aec0")
        
        # Append some active stats
        total_active_geos = len(clean_destinations) + len(malicious_destinations)
        text.append(f" Total Geolocated Targets: {total_active_geos}  |  Malicious: {len(malicious_destinations)}", style="dim #a0aec0")
        
        return text

class MapScreen(Screen):
    """Fullscreen screen that displays the interactive map."""
    
    BINDINGS = [
        Binding("m", "close_map", "Toggle Dashboard View"),
        Binding("escape", "close_map", "Back to Dashboard"),
    ]
    
    def compose(self) -> ComposeResult:
        from main import NetTraceHeader
        yield NetTraceHeader()
        with Container(id="fullscreen-map-container"):
            yield WorldMapWidget(id="fullscreen-map")
        yield Footer()
        
    def action_close_map(self) -> None:
        self.app.pop_screen()
