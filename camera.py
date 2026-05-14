import cv2

class Camera:
    def __init__(self):
        self.video = cv2.VideoCapture(0)  # Default webcam (0); change if needed

    def __del__(self):
        self.video.release()

    def get_frame(self):
        success, image = self.video.read()
        if success:
            ret, jpeg = cv2.imencode('.jpg', image)
            return jpeg.tobytes()
        return b''
