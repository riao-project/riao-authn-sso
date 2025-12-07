import { Authentication, Principal, Encryptor, Decryptor } from '@riao/iam';
import { QueryRepository, DatabaseRecordId } from '@riao/dbal';
import { randomBytes } from 'crypto';
import {
	SSOTokenRecord,
	SSOUserInfo,
	SSOTokenResponse,
	SSOAuthenticationOptions,
	SSOStateRecord,
} from './sso-config';

/**
 * Generic OAuth2/OIDC SSO authentication driver
 * Extend for specific SSO providers (Entra, Google, Okta, etc.)
 */
export abstract class SSOAuthentication<
	TPrincipal extends Principal,
> extends Authentication<TPrincipal> {
	protected readonly provider: string;
	protected readonly stateExpiryMinutes: number;
	protected ssoTokenRepo: QueryRepository<SSOTokenRecord>;
	protected ssoStateRepo: QueryRepository<SSOStateRecord>;
	protected encryptor?: Encryptor;
	protected decryptor?: Decryptor;

	constructor(options: SSOAuthenticationOptions) {
		super(options);
		this.provider = options.provider;
		this.stateExpiryMinutes = options.stateExpiryMinutes || 10;
		this.ssoTokenRepo = options.db.getQueryRepository<SSOTokenRecord>({
			table: 'iam_sso_tokens',
			identifiedBy: 'id',
		});
		this.ssoStateRepo = options.db.getQueryRepository<SSOStateRecord>({
			table: 'iam_sso_state',
			identifiedBy: 'state',
		});
		// Initialize encryption/decryption if keys provided
		if (options.encryptionPublicKey) {
			this.encryptor = new Encryptor(options.encryptionPublicKey);
		}
		if (options.encryptionPrivateKey) {
			this.decryptor = new Decryptor(options.encryptionPrivateKey);
		}
	}

	/**
	 * Get authorization URL for redirecting user to provider
	 * Must be implemented by subclass
	 */
	abstract getAuthorizationUrl(state: string): string;

	/**
	 * Get authorization URL query parameters
	 * Must be implemented by subclass
	 */
	protected abstract getAuthorizationParams(
		state: string
	): Record<string, string>;

	/**
	 * Exchange authorization code for access/refresh tokens
	 * Must be implemented by subclass
	 */
	abstract exchangeAuthorizationCode(code: string): Promise<SSOTokenResponse>;

	/**
	 * Get user information from provider using access token
	 * Must be implemented by subclass
	 */
	protected abstract getUserInfo(accessToken: string): Promise<SSOUserInfo>;

	/**
	 * Exchange refresh token for new tokens
	 * Must be implemented by subclass
	 */
	protected abstract exchangeRefreshToken(
		refreshToken: string
	): Promise<SSOTokenResponse>;

	/**
	 * Generic authenticate implementation
	 * Orchestrates: code exchange → user info → principal → tokens
	 * Validates state parameter for CSRF protection if provided
	 */
	public override async authenticate(credentials: {
		code: string;
		state?: string;
	}): Promise<TPrincipal | null> {
		// Validate state if provided for CSRF protection
		if (credentials.state) {
			await this.validateState(credentials.state);
		}

		// Exchange code for tokens
		const tokenData = await this.exchangeAuthorizationCode(
			credentials.code
		);

		// Get user info from provider
		const userInfo = await this.getUserInfo(tokenData.access_token);

		// Find existing principal or create new one
		let principal = await this.findActivePrincipal({
			where: <TPrincipal>{
				login: userInfo.login,
			},
		});

		if (!principal) {
			// Create new principal if it doesn't exist
			const principalData = {
				login: userInfo.login,
				name: userInfo.name,
				type: userInfo.type,
			};
			const newPrincipalId = await this.createPrincipal(
				principalData as unknown as TPrincipal
			);

			principal = await this.findActivePrincipal({
				where: <TPrincipal>{ id: newPrincipalId },
			});

			if (!principal) {
				return null;
			}
		}

		// Store or update SSO tokens
		await this.saveTokens(principal.id, userInfo.id, tokenData, userInfo);

		return principal;
	}

	/**
	 * Save or update SSO tokens in database
	 * Encrypts tokens before storage if encryption is configured
	 */
	protected async saveTokens(
		principalId: DatabaseRecordId,
		providerId: string,
		tokenData: SSOTokenResponse,
		userInfo: SSOUserInfo
	): Promise<void> {
		const expiresAt = new Date(Date.now() + tokenData.expires_in * 1000);

		const existing = await this.ssoTokenRepo.findOne({
			where: {
				principal_id: principalId,
				provider: this.provider,
			},
		});

		const record: Partial<SSOTokenRecord> = {
			provider_id: providerId,
			provider: this.provider,
			access_token: this.encryptor
				? this.encryptor
					.encrypt(tokenData.access_token)
					.toString('base64')
				: tokenData.access_token,
			refresh_token: tokenData.refresh_token
				? this.encryptor
					? this.encryptor
						.encrypt(tokenData.refresh_token)
						.toString('base64')
					: tokenData.refresh_token
				: undefined,
			expires_at: expiresAt,
			provider_metadata: JSON.stringify(userInfo),
		};

		if (existing) {
			await this.ssoTokenRepo.update({
				set: record,
				where: { id: existing.id },
			});
		}
		else {
			await this.ssoTokenRepo.insert({
				records: [
					{
						principal_id: principalId,
						...record,
					} as SSOTokenRecord,
				],
			});
		}
	}

	/**
	 * Refresh access token using refresh token
	 * Decrypts stored refresh token and re-encrypts new tokens
	 */
	public async refreshAccessToken(
		principalId: DatabaseRecordId
	): Promise<string | null> {
		const tokenRecord = await this.ssoTokenRepo.findOne({
			where: {
				principal_id: principalId,
				provider: this.provider,
			},
		});

		if (!tokenRecord?.refresh_token) {
			return null;
		}

		// Decrypt refresh token if encryption is configured
		const refreshToken = this.decryptor
			? this.decryptor
				.decrypt(Buffer.from(tokenRecord.refresh_token, 'base64'))
				.toString('utf-8')
			: tokenRecord.refresh_token;

		const newTokenData = await this.exchangeRefreshToken(refreshToken);

		await this.ssoTokenRepo.update({
			set: {
				access_token: this.encryptor
					? this.encryptor
						.encrypt(newTokenData.access_token)
						.toString('base64')
					: newTokenData.access_token,
				refresh_token: newTokenData.refresh_token
					? this.encryptor
						? this.encryptor
							.encrypt(newTokenData.refresh_token)
							.toString('base64')
						: newTokenData.refresh_token
					: undefined,
				expires_at: new Date(
					Date.now() + newTokenData.expires_in * 1000
				),
			},
			where: { id: tokenRecord.id },
		});

		return this.encryptor
			? this.encryptor
				.encrypt(newTokenData.access_token)
				.toString('base64')
			: newTokenData.access_token;
	}

	/**
	 * Get stored token for principal
	 * Decrypts tokens if encryption is configured
	 */
	public async getStoredToken(
		principalId: DatabaseRecordId
	): Promise<SSOTokenRecord | null> {
		const record = await this.ssoTokenRepo.findOne({
			where: {
				principal_id: principalId,
				provider: this.provider,
			},
		});

		if (!record) {
			return null;
		}

		// Decrypt tokens if encryption is configured
		if (this.decryptor) {
			return {
				...record,
				access_token: this.decryptor
					.decrypt(Buffer.from(record.access_token, 'base64'))
					.toString('utf-8'),
				refresh_token: record.refresh_token
					? this.decryptor
						.decrypt(
							Buffer.from(record.refresh_token, 'base64')
						)
						.toString('utf-8')
					: undefined,
			};
		}

		return record;
	}

	/**
	 * Revoke SSO session/tokens for principal
	 */
	public async revokeSession(principalId: DatabaseRecordId): Promise<void> {
		await this.ssoTokenRepo.delete({
			where: {
				principal_id: principalId,
				provider: this.provider,
			},
		});
	}

	/**
	 * Generate a cryptographically random state parameter for CSRF protection
	 */
	public async generateState(): Promise<string> {
		const state = randomBytes(32).toString('hex');
		const now = new Date();
		// eslint-disable-next-line max-len
		const expiresAt = new Date(
			now.getTime() + this.stateExpiryMinutes * 60000
		);

		await this.ssoStateRepo.insert({
			records: [
				{
					state,
					provider: this.provider,
					created_at: now,
					expires_at: expiresAt,
				} as SSOStateRecord,
			],
		});

		return state;
	}

	/**
	 * Validate and consume state parameter for CSRF protection
	 */
	public async validateState(state: string): Promise<boolean> {
		const record = await this.ssoStateRepo.findOne({
			where: {
				state,
				provider: this.provider,
			},
		});

		if (!record) {
			throw new Error('State validation failed or state not found');
		}

		const now = new Date();
		if (record.expires_at < now) {
			throw new Error('State has expired');
		}

		if (record.used_at) {
			throw new Error('State has been consumed');
		}

		// Mark state as used
		await this.ssoStateRepo.update({
			set: { used_at: now },
			where: { state },
		});

		return true;
	}

	/**
	 * Get stored state info
	 */
	public async getStoredState(state: string): Promise<SSOStateRecord | null> {
		return this.ssoStateRepo.findOne({
			where: {
				state,
				provider: this.provider,
			},
		});
	}

	/**
	 * Clean up expired state records
	 */
	public async cleanupExpiredStates(): Promise<void> {
		// Note: This is a simplified cleanup. For production use,
		// consider implementing a more efficient bulk delete with
		// raw SQL or ORM-specific expiration query syntax
		const expiredStates = await this.ssoStateRepo.find({
			where: {
				provider: this.provider,
			},
		});

		const now = new Date();
		const statesToDelete = expiredStates
			.filter((state) => state.expires_at < now)
			.map((state) => state.state);

		if (statesToDelete.length > 0) {
			await Promise.all(
				statesToDelete.map(async (state) =>
					this.ssoStateRepo.delete({
						where: {
							state,
							provider: this.provider,
						},
					})
				)
			);
		}
	}

	/**
	 * Generate authorization URL with state parameter
	 */
	public async generateAuthorizationUrl(): Promise<{
		url: string;
		state: string;
	}> {
		const state = await this.generateState();
		const url = this.getAuthorizationUrl(state);
		return { url, state };
	}
}
