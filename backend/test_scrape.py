import urllib.request
import re

url = "https://www.google.com/search?ibp=oshop&q=Meal+delivery+subscription+New+York%2C+USA&prds=localAnnotatedOfferId:1,catalogid:10980778425077577386,pvo:2,pvt:hg,rds:PC_6027158597472037202%7CPROD_PC_6027158597472037202&gl=us&udm=28&pvorigin=2"

req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
try:
    with urllib.request.urlopen(req) as resp:
        html = resp.read().decode('utf-8')
        
        # Look for the Clean Eatz URL in the HTML
        if "cleaneatzkitchen" in html:
            print("Found target domain in HTML!")
            urls = re.findall(r'https?://[^\s\"\'<>]+', html)
            for u in urls:
                if "cleaneatzkitchen" in u:
                    print("Match:", u)
        else:
            print("Target domain not found. Saving HTML.")
            with open("test_google.html", "w", encoding="utf-8") as f:
                f.write(html)
except Exception as e:
    print("Failed:", e)
