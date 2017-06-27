import { HexBase64BinaryEncoding } from 'crypto';
export interface CipherOptions {
	saltSize?: number;
	algorithm?: string;
	encoded?: HexBase64BinaryEncoding;
}
export type CallBack = <V>(err: Error, encrypted: V) => void;