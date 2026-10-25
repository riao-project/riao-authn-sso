import { DatabaseRecordId } from '@riao/dbal';
import { AuthenticationOptions } from '@riao/iam/authentication';
import * as crypto from 'crypto';

/**
 * SSO authentication configuration options
 */
export interface SSOAuthenticationOptions extends AuthenticationOptions {
	provider: string;
	// eslint-disable-next-line max-len
	stateExpiryMinutes?: number; // Expiry time for state parameter (default: 10)
	requestTimeoutMs?: number;
	// Token encryption keys (optional)
	encryptionPublicKey?: crypto.KeyObject;
	encryptionPrivateKey?: crypto.KeyObject;
}

/**
 * State record stored for CSRF protection
 */
export interface SSOStateRecord {
	state: string;
	provider: string;
	principal_id?: DatabaseRecordId;
	created_at: Date;
	expires_at: Date;
	used_at?: Date;
	consumption_id?: string;
}

/**
 * Token record stored for each SSO provider
 */
export interface SSOTokenRecord {
	id: string;
	principal_id: DatabaseRecordId;
	provider_id: string; // User ID from provider
	provider: string; // 'entra', 'google', 'okta', etc.
	refresh_token?: string;
	access_token: string;
	expires_at: Date;
	provider_metadata?: string; // JSON for extra provider data
	created_at?: Date;
	updated_at?: Date;
}

/**
 * Standardized user info from SSO provider
 */
export interface SSOUserInfo {
	id: string;
	login: string;
	name: string;
	type: string;
	// For provider-specific claims
	[key: string]: string | undefined;
}

/**
 * Token exchange response from provider
 */
export interface SSOTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in: number;
	token_type?: string;
	// For provider-specific response data
	[key: string]: string | number | undefined;
}
