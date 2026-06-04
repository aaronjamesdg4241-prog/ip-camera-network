import cv2
import threading
import time
import numpy as np
from flask import Flask, Response
from queue import Queue
import os

app = Flask(__name__)
frame_queue = Queue(maxsize=2)

# Move the camera logic into a wrapper that starts only when needed
def capture_obs():
    print("[INFO] Starting capture thread...")
    CAMERA_INDEX = 1
    
    # Graceful handling for cloud environments
    try:
        cap = cv2.VideoCapture(CAMERA_INDEX, cv2.CAP_DSHOW if os.name == 'nt' else cv2.CAP_ANY)
    except Exception:
        cap = None

    while True:
        if cap is None or not cap.isOpened():
            time.sleep(5) # Wait before retrying
            continue
            
        ret, frame = cap.read()
        if ret:
            ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 50])
            if ret:
                if frame_queue.qsize() < 2:
                    frame_queue.put(buffer.tobytes())
        time.sleep(0.03)

# Start thread only if not already running
threading.Thread(target=capture_obs, daemon=True).start()

@app.route('/')
def index():
    return "Stream portal active."

@app.route('/video_feed')
def video_feed():
    def generate():
        while True:
            frame = frame_queue.get()
            yield (b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
    return Response(generate(), mimetype='multipart/x-mixed-replace; boundary=frame')
