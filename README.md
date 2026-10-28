# CertiSure · Certificate Authenticity Verifier

## 🎯 Problem Statement 
**Backstory:** College events are often crashed by people carrying fake or forged participation certificates to claim attendance credit they didn't earn. Organizers have no quick way to tell a genuine certificate from a forged one, especially during busy event verification.
> 
> **Solution:** Building a system where an organizer issues each certificate with a unique ID, QR code, and live attendee photo at the time of issuance, storing a matching record in a simple database. A verifier scans the QR code and captures a live attendee face photo to get an instant **genuine**, **forged**, or **not-found** result — no manual cross-checking needed.

---

## ⚡ Key Updates & Features

1. Removed Steganography Signature:
   - Eliminated the cumbersome LSB hidden signature file uploading.
2. Added Live Attendee Photo Capture:
   - **At Issuance**: Organizers snap a live webcam photo of the student (or upload a photo). The photo is embedded directly onto the pass credential card and saved in the SQLite database.
   - **At Checkpoint **: Verifiers point the camera at the attendee standing in front of them to take a live desk snapshot.
   - **Visual Cross-Check**: Side-by-side comparison of the **Registered Photo** vs. **Live Desk Snapshot** instantly proves whether the person presenting the certificate is the actual owner (eliminating certificate sharing and impersonation).
3. Instant QR Verification :
   - Verifies the cryptographic fingerprint of the certificate record in Firebase.
   -    - Flags suspicious repeated-scanning attempts .

---

