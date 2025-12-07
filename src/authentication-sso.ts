import { Authentication, Principal } from '@riao/iam';
import { QueryRepository, DatabaseRecordId } from '@riao/dbal';
import {
	SSOTokenRecord,
	SSOUserInfo,
	SSOTokenResponse,
	SSOAuthenticationOptions,
} from './sso-config';

/**
 * Generic OAuth2/OIDC SSO authentication driver
 * Extend for specific SSO providers (Entra, Google, Okta, etc.)
 */
export abstract class SSOAuthentication<
	TPrincipal extends Principal,
> extends Authentication<TPrincipal> {
	protected readonly provider: string;
	protected ssoTokenRepo: QueryRepository<SSOTokenRecord>;

	constructor(options: SSOAuthenticationOptions) {
		super(options);
		this.provider = options.provider;
		this.ssoTokenRepo = options.db.getQueryRepository<SSOTokenRecord>({
			table: 'iam_sso_tokens',
			identifiedBy: 'id',
		});
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
	 */
	public override async authenticate(credentials: {
		code: string;
		state?: string;
	}): Promise<TPrincipal | null> {
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
			access_token: tokenData.access_token,
			refresh_token: tokenData.refresh_token,
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

		const newTokenData = await this.exchangeRefreshToken(
			tokenRecord.refresh_token
		);

		await this.ssoTokenRepo.update({
			set: {
				access_token: newTokenData.access_token,
				refresh_token: newTokenData.refresh_token,
				expires_at: new Date(
					Date.now() + newTokenData.expires_in * 1000
				),
			},
			where: { id: tokenRecord.id },
		});

		return newTokenData.access_token;
	}

	/**
	 * Get stored token for principal
	 */
	public async getStoredToken(
		principalId: DatabaseRecordId
	): Promise<SSOTokenRecord | null> {
		return this.ssoTokenRepo.findOne({
			where: {
				principal_id: principalId,
				provider: this.provider,
			},
		});
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
}
