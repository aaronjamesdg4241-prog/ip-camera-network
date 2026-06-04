from flask import Flask, render_template_string
import os

app = Flask(__name__)

# IMPORTANT: Replace this with your specific ZROK public URL
# It must include the "/video_feed" path
ZROK_STREAM_URL = "https://fx4og87yqkex.shares.zrok.io/video_feed"

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Live CCTV Stream</title>
    <style>
        body { background: #0f172a; color: white; text-align: center; font-family: sans-serif; padding: 20px; }
        img { 
            width: 100%; 
            max-width: 854px; 
            border: 3px solid #3b82f6; 
            border-radius: 12px; 
            background: #000; 
        }
        .status { margin-top: 20px; color: #10b981; }
    </style>
</head>
<body>
    <h1>🎥 Live CCTV Stream</h1>
    <img src="{{ stream_url }}" alt="Live Feed">
    <div class="status">● Status: Connected to Zrok Tunnel</div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, stream_url=ZROK_STREAM_URL)

if __name__ == '__main__':
    # Railway will provide the PORT
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
