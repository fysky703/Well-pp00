import { BrowserQRCodeReader, IScannerControls } from '@zxing/browser';
import { isValidBase32, ParsedOTPAuth, parseOTPAuthURI } from './totp';

export class QRScannerService {
  private codeReader: BrowserQRCodeReader;
  private controls: IScannerControls | null = null;

  constructor() {
    this.codeReader = new BrowserQRCodeReader();
  }

  /**
   * Starts the video stream on the given video element and listens for QR codes.
   */
  public async startScanning(
    videoElement: HTMLVideoElement,
    onSuccess: (result: ParsedOTPAuth) => void,
    onError: (errorMsg: string) => void
  ) {
    try {
      this.stopScanning();

      this.controls = await this.codeReader.decodeFromVideoDevice(
        undefined, // Uses default rear camera (environment)
        videoElement,
        (result, error, controls) => {
          if (result) {
            const rawText = result.getText();
            
            // 1. Verify URI starts with otpauth://
            if (!rawText.startsWith('otpauth://')) {
              onError('Scanned QR is not a valid 2FA authenticator QR code.');
              return;
            }

            // 2. Parse otpauth:// format
            const parsed = parseOTPAuthURI(rawText);
            if (!parsed) {
              onError('Invalid TOTP URI format in QR code.');
              return;
            }

            // 3. Strict Base32 Secret Validation
            if (!isValidBase32(parsed.secret)) {
              onError('The secret key in this QR code is not a valid Base32 string.');
              return;
            }

            // Stop camera on success and return parsed account data
            controls.stop();
            this.controls = null;
            onSuccess(parsed);
          }
        }
      );
    } catch (err: any) {
      console.error('Camera Init Error:', err);
      onError(
        err.name === 'NotAllowedError'
          ? 'Camera permission denied. Please grant camera access in your browser settings.'
          : 'Unable to access camera: ' + (err.message || 'Unknown device error')
      );
    }
  }

  /**
   * Stops active camera stream and releases media hardware.
   */
  public stopScanning() {
    if (this.controls) {
      this.controls.stop();
      this.controls = null;
    }
  }
}

export const qrScanner = new QRScannerService();