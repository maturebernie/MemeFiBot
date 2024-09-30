import aiohttp
import aiocfscrape
import asyncio
from aiohttp_socks import ProxyConnector
import logging
import ssl

# Set up logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the proxy and SSL context
proxy = "socks5://lhpxktqv:okbnbtjht75y@104.143.245.205:6445"
CIPHERS = [
    "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256", "AES256-GCM-SHA384", "AES128-SHA", "AES256-SHA", "DES-CBC3-SHA",
    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256", "TLS_AES_256_CCM_8_SHA256"
]
ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
ssl_context.set_ciphers(':'.join(CIPHERS))
ssl_context.set_ecdh_curve("prime256v1")
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
async def check_proxy(http_client: aiohttp.ClientSession, proxy: str) -> None:
    """Check if the proxy is working and log the IP."""
    try:
        response = await http_client.get(url='https://api.ipify.org?format=json', timeout=aiohttp.ClientTimeout(5))
        ip = (await response.json()).get('ip')
        logger.info(f"Proxy IP: {ip}")
    except Exception as error:
        logger.error(f"Proxy: {proxy} | Error: {error}")

async def fetch_with_proxy(proxy: str):
    """Main function to use proxy and fetch data."""
    conn = ProxyConnector().from_url(url=proxy, rdns=True, ssl=ssl_context) if proxy \
        else aiohttp.TCPConnector(ssl=ssl_context)

    async with aiocfscrape.CloudflareScraper(headers={'User-Agent': 'Mozilla/5.0'}, connector=conn) as http_client:
        logger.info(f"{proxy} is being used")
        if proxy:
            await check_proxy(http_client=http_client, proxy=proxy)

def main():
    """Synchronous entry point to run the async code."""
    asyncio.run(fetch_with_proxy(proxy))

if __name__ == "__main__":
    main()
