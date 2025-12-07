import { DatabaseRecordId, Database } from '@riao/dbal';
import { AuthOptions } from '@riao/iam/auth/auth';

/**
 * SSO authentication configuration options
 */
export interface SSOAuthenticationOptions extends AuthOptions {
	db: Database;
	provider: string;
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
	[key: string]: string | undefined; // For provider-specific claims
}

/**
 * Token exchange response from provider
 */
export interface SSOTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in: number;
	token_type?: string;
	[key: string]: string | number | undefined; // For provider-specific
}
