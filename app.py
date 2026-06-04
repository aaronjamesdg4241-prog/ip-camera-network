import cv2
import threading
import time
import numpy as np
from flask import Flask, Response
from queue import Queue
import os

app = Flask(__name__)
frame_queue = Queue(maxsize=2)

def capture_obs():
    """Capture from OBS Virtual Camera (Index 1) with headless environment safety."""
    print("[INFO] Connecting to OBS Virtual Camera at index 1...")
    
    CAMERA_INDEX = 1
    
    # On headless cloud environments (like Railway), index 1 won't exist.
    # We trap the initialization so the thread handles the failure gracefully.
    try:
        cap = cv2.VideoCapture(CAMERA_INDEX, cv2.CAP_DSHOW if os.name == 'nt' else cv2.CAP_ANY)
        if not cap.isOpened():
            print("[ERROR] Cannot open camera index 1! Operating in cloud/fallback dummy mode.")
            cap = None
    except Exception as e:
        print(f"[ERROR] Native video framework exception: {e}. Defaulting to dummy stream.")
        cap = None

    if cap is not None:
        print("[SUCCESS] Connected to OBS Virtual Camera!")
        # Configure camera hardware properties
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 854)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        cap.set(cv2.CAP_PROP_FPS, 30)
        print("[INFO] Starting hardware frame capture loop...")
    
    frame_count = 0
    last_fps_log = time.time()
    
    while True:
        # If camera is down or on a headless server, skip reading and let generator show placeholder
        if cap is None or not cap.isOpened():
            time.sleep(1.0)
            continue
            
        ret, frame = cap.read()
        
        if ret and frame is not None:
            frame_count += 1
            
            # Log operational FPS performance data every 5 seconds
            if time.time() - last_fps_log >= 5:
                fps = frame_count / 5
                print(f"[LIVE] Streaming from local hardware at {fps:.1f} FPS")
                frame_count = 0
                last_fps_log = time.time()
            
            # Embed status timestamp matrix overlay directly into frame
            cv2.putText(frame, f"OBS Virtual Camera | {time.strftime('%H:%M:%S')}",
                        (20, 40), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
            
            # Encode frame array to low-latency high-compression JPEG formats
            ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 75])
            
            if ret:
                # Thread-safe pipeline flush: Keep only the freshest frames in queue
                while frame_queue.qsize() >= 2:
                    try:
                        frame_queue.get_nowait()
                    except:
                        pass
                frame_queue.put(buffer.tobytes())
        else:
            print("[WARNING] Empty frame payload received from hardware source")
            time.sleep(0.1)
        
        time.sleep(0.033)  # Throttle runtime pacing to maintain ~30 FPS profile

def generate_frames():
    """Generate frames for multipart web stream output."""
    while True:
        try:
            # Fetch latest frame out of the tracking buffer queue
            frame_bytes = frame_queue.get(timeout=0.5)
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
        except:
            # Render and yield high-visibility placeholder state image if frame streams are dead
            placeholder = np.zeros((480, 854, 3), dtype=np.uint8)
            cv2.putText(placeholder, "Waiting for OBS Virtual Camera Tunnel...", (160, 220),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
            cv2.putText(placeholder, "Ensure local zrok proxy and OBS Virtual Cam are active.", (140, 270),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
            
            ret, buffer = cv2.imencode('.jpg', placeholder)
            if ret:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
            time.sleep(0.1)

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>OBS Virtual Camera Stream</title>
        <style>
            body {
                background: #0f172a;
                text-align: center;
                color: white;
                font-family: 'Segoe UI', Arial, sans-serif;
                padding: 20px;
                margin: 0;
            }
            .container { max-width: 1200px; margin: 0 auto; }
            img {
                width: 100%;
                max-width: 854px;
                border: 3px solid #3b82f6;
                border-radius: 12px;
                background: #000;
                box-shadow: 0 0 30px rgba(59,130,246,0.3);
            }
            .status { color: #3b82f6; font-weight: bold; margin-top: 20px; font-size: 18px; }
            .info {
                background: #1e293b;
                padding: 15px;
                border-radius: 8px;
                margin-top: 20px;
                font-size: 14px;
                text-align: left;
                max-width: 600px;
                margin-left: auto;
                margin-right: auto;
            }
            .success { color: #10b981; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎥 OBS Virtual Camera Stream</h1>
            <img src="/video_feed" id="stream">
            <div class="status">
                <span class="success">● ONLINE</span> Stream pipeline initialized
            </div>
            <div class="info">
                <strong>📹 Source Transport Configuration:</strong><br>
                • Targeting Interface: Index 1 (OBS Virtual Camera Context)<br>
                • Video Geometry: 854x480 resolution matrix @ ~30fps<br>
                • Distribution Method: MJPEG Multipart Stream Proxy Tunnel via zrok
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/video_feed')
def video_feed():
    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# Auto-start capture background daemon immediately upon script load.
# This prevents Gunicorn imports from stalling on terminal input locks.
capture_thread = threading.Thread(target=capture_obs, daemon=True)
capture_thread.start()

if __name__ == '__main__':
    # Reading clean dynamic environment target ports bound by web proxy assignments
    target_port = int(os.environ.get("PORT", 5000))
    print("="*60)
    print(f"🌐 NATIVE INSTANCE INITIALIZED. BINDING TO PORT: {target_port}")
    print("="*60)
    app.run(host='0.0.0.0', port=target_port, debug=False, threaded=True)
