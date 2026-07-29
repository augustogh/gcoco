import logging
import ipaddress
import aiohttp
from typing import Optional, Dict, Tuple
from cachetools import TTLCache

# Configure logger for threat intel
logger = logging.getLogger("threat_intel")

# In-memory cache for IP verification results
# Cache up to 1024 IPs for 1 hour (3600 seconds)
ip_cache = TTLCache(maxsize=1024, ttl=3600)

# Geolocation cache in memory (IP to Lat, Lon tuple)
geo_cache: Dict[str, Tuple[float, float]] = {}

def is_public_ip(ip_str: str) -> bool:
    """Checks if an IP address is a valid public IP."""
    if not ip_str or ip_str in ("*", "0.0.0.0", "::"):
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        # Check if the IP is global (i.e. not private, loopback, link-local, multicast, etc.)
        return ip.is_global and not ip.is_multicast and not ip.is_loopback and not ip.is_private and not ip.is_reserved
    except ValueError:
        return False

async def query_virustotal_ip(ip: str, api_key: str) -> Optional[bool]:
    """
    Queries VirusTotal API v3 for the reputation of a public IP address.
    Returns:
        True: if the IP is malicious or suspicious.
        False: if the IP is clean/undetected.
        None: if the query could not be completed (e.g. rate limit, no API key, or invalid IP).
    """
    if not api_key:
        return None

    if not is_public_ip(ip):
        return False

    # Check cache first
    if ip in ip_cache:
        return ip_cache[ip]

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    
                    is_malicious = (malicious > 0 or suspicious > 0)
                    ip_cache[ip] = is_malicious
                    return is_malicious
                
                elif response.status == 429:
                    # Silence 429 Too Many Requests to prevent log spam and respect free limits
                    logger.debug(f"VirusTotal API rate limit hit (429) for IP: {ip}")
                    return None
                
                elif response.status == 401 or response.status == 403:
                    logger.warning(f"VirusTotal API authentication error ({response.status}). Check vt_api_key configuration.")
                    return None
                
                else:
                    logger.debug(f"VirusTotal API returned status {response.status} for IP: {ip}")
                    return None

    except aiohttp.ClientError as e:
        logger.debug(f"Aiohttp connection error to VirusTotal: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error querying VirusTotal for IP {ip}: {e}")
        return None

async def get_ip_geolocation(ip: str) -> Optional[Tuple[float, float]]:
    """
    Asynchronously queries ip-api.com for the latitude and longitude of a public IP.
    Results are cached in geo_cache.
    """
    if not is_public_ip(ip):
        return None

    if ip in geo_cache:
        return geo_cache[ip]

    url = f"http://ip-api.com/json/{ip}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "success":
                        lat = data.get("lat")
                        lon = data.get("lon")
                        if lat is not None and lon is not None:
                            geo_cache[ip] = (float(lat), float(lon))
                            logger.info(f"Geolocated IP {ip} at ({lat}, {lon})")
                            return geo_cache[ip]
                    logger.debug(f"ip-api query status failed for IP {ip}: {data}")
    except Exception as e:
        logger.debug(f"Error querying geolocation for IP {ip}: {e}")
    return None

async def get_own_geolocation() -> Optional[Tuple[float, float]]:
    """
    Asynchronously queries ip-api.com to find the latitude and longitude of the current host.
    """
    url = "http://ip-api.com/json/"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "success":
                        lat = data.get("lat")
                        lon = data.get("lon")
                        if lat is not None and lon is not None:
                            logger.info(f"Geolocated origin host at ({lat}, {lon})")
                            return (float(lat), float(lon))
    except Exception as e:
        logger.debug(f"Error querying own geolocation: {e}")
    return None

