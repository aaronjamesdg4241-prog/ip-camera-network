from flask import Flask
import os

app = Flask(__name__)

# Replace with your actual ZROK public URL
ZROK_STREAM_URL = "https://fx4og87yqkex.shares.zrok.io/video_feed"

@app.route('/')
def index():
    return f'''
    <html>
        <body style="background:#0f172a; color:white; text-align:center; font-family:sans-serif;">
            <h1>🎥 Live CCTV Stream</h1>
            <img src="{ZROK_STREAM_URL}" style="max-width:854px; width:100%; border:3px solid #3b82f6; border-radius:12px;">
        </body>
    </html>
    '''

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
