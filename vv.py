import cv2

capture = cv2.VideoCapture(0)
face_algorith = cv2.CascadeClassifier("algorith/haar_face.xml")
while True:
    _, img = capture.read()
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    draw_capture = face_algorith.detectMultiScale(gray, 1.3, 5, minSize=(30, 30), flags=cv2.CASCADE_SCALE_IMAGE)
    for (x, y, w, h) in draw_capture:
        cv2.rectangle(img, (x, y), (x+w, y+h), (129, 37, 58), 2)
    cv2.imshow("Capture", img)
    if cv2.waitKey(1) & 0xFF == ord("d"):
        break
    print("Camera is working properly...")
    capture.release()

    cv2.destroyAllWindows()


