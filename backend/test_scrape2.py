import urllib.request
import re
import urllib.parse
from html import unescape

urls_to_test = [
    "https://www.google.com/search?ibp=oshop&q=Meal+delivery+subscription+New+York%2C+USA&prds=localAnnotatedOfferId:1,catalogid:10980778425077577386,pvo:2,pvt:hg,rds:PC_6027158597472037202%7CPROD_PC_6027158597472037202&gl=us&udm=28&pvorigin=2",
    "https://www.google.com/search?ibp=oshop&q=Circadian+light+lamp+New+York%2C+USA&prds=localAnnotatedOfferId:1,productid:17409851786205622756,pvo:2,pvt:hg,rds:PC_6027158597472037202%7CPROD_PC_6027158597472037202&gl=us&udm=28&pvorigin=2",
    "https://www.google.com/search?ibp=oshop&q=Blue+light+glasses+New+York%2C+USA&prds=localAnnotatedOfferId:1,catalogid:14462391149340257203,pvo:2,pvt:hg,rds:PC_6027158597472037202%7CPROD_PC_6027158597472037202&gl=us&udm=28&pvorigin=2"
]

for url in urls_to_test:
    print(f"\nTesting URL: {url[:100]}...")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'})
    try:
        with urllib.request.urlopen(req) as resp:
            html = resp.read().decode('utf-8')
            
            # Google often places the outbound URL in a redirect link like /url?q=... or /url?url=...
            # The HTML returned by Google sometimes has it URL-encoded and HTML-escaped.
            
            # Find all potential absolute URLs inside the document
            # The actual product URL will definitely NOT be a google or gstatic domain.
            all_urls = re.findall(r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s\"\'<>\\]*)?', html)
            
            found_product = None
            for u in all_urls:
                u = urllib.parse.unquote(unescape(u))
                if not any(x in u for x in ['google.com', 'google.ng', 'gstatic.com', 'schema.org', 'w3.org', 'youtube.com']):
                    if 'google' not in urllib.parse.urlparse(u).netloc:
                        found_product = u
                        break
            
            print("Extracted Direct URL:", found_product)
            
    except Exception as e:
        print("Failed:", e)
