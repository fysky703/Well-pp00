import { Request, Response } from 'express';
import { app } from './app';

export default async function handler(req: Request, res: Response) {
  try {
    return app(req, res);
  } catch (error: any) {
    console.error('Serverless Handler Error:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: error?.message || 'Unknown error'
    });
  }
}