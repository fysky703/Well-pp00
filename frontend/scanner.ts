import { BrowserQRCodeReader, IScannerControls } from '@zxing/browser';
import { isValidBase32, ParsedOTPAuth, parseOTPAuthURI } from './totp';

export class QRScannerService {
  private codeReader: BrowserQRCodeReader;
  private controls: IScannerControls | null = null;

  constructor() {
    this.codeReader = new BrowserQRCodeReader();
  }

  public async startScanning(
    videoElement: HTMLVideoElement,
    onSuccess: (result: ParsedOTPAuth) => void,
    onError: (errorMsg: string) => void
  ) {
    try {
      this.stopScanning();

      this.controls = await this.codeReader.decodeFromVideoDevice(
        undefined,
        videoElement,
        (result, _error, controls) => {
          if (result) {
            const rawText = result.getText();
            
            if (!rawText.startsWith('otpauth://')) {
              onError('Scanned QR code is not a valid otpauth:// format.');
              return;
            }

            const parsed = parseOTPAuthURI(rawText);
            if (!parsed) {
              onError('Invalid TOTP URI format in QR code.');
              return;
            }

            if (!isValidBase32(parsed.secret)) {
              onError('The secret key in this QR code is not valid Base32.');
              return;
            }

            controls.stop();
            this.controls = null;
            onSuccess(parsed);
          }
        }
      );
    } catch (err: any) {
      onError(
        err.name === 'NotAllowedError'
          ? 'Camera permission denied.'
          : 'Camera error: ' + (err.message || 'Unknown device error')
      );
    }
  }

  public stopScanning() {
    if (this.controls) {
      this.controls.stop();
      this.controls = null;
    }
  }
}

export const qrScanner = new QRScannerService();