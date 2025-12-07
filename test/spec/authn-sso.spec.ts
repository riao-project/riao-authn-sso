import 'jasmine';
import { SSOAuthentication, SSOTokenResponse, SSOUserInfo } from '../../src';
import { createDatabase, getMigrations, runMigrations } from '../database';
import { Principal, KeyPairGenerator } from '@riao/iam';
import { AuthenticationSSOMigrations } from '../../src/authentication-sso-migrations'; // eslint-disable-line max-len
import { AuthMigrations } from '@riao/iam/auth/auth-migrations';

interface SSOPrincipal extends Principal {
	name: string;
}

/**
 * Test implementation of SSOAuthentication for testing purposes
 */
class TestSSOAuthentication extends SSOAuthentication<SSOPrincipal> {
	getAuthorizationUrl(state: string): string {
		return `https://provider.example.com/authorize?state=${state}`;
	}

	protected getAuthorizationParams(state: string): Record<string, string> {
		return {
			client_id: 'test-client-id',
			redirect_uri: 'http://localhost:3000/callback',
			scope: 'openid profile email',
			state,
		};
	}

	async exchangeAuthorizationCode(code: string): Promise<SSOTokenResponse> {
		// Mock implementation
		if (code === 'valid-code') {
			return {
				access_token: 'test-access-token',
				refresh_token: 'test-refresh-token',
				expires_in: 3600,
				token_type: 'Bearer',
			};
		}
		throw new Error('Invalid authorization code');
	}

	protected async getUserInfo(accessToken: string): Promise<SSOUserInfo> {
		// Mock implementation
		if (accessToken === 'test-access-token') {
			return {
				id: 'provider-user-123',
				login: 'testuser@example.com',
				name: 'Test User',
				type: 'user',
			};
		}
		throw new Error('Invalid access token');
	}

	protected async exchangeRefreshToken(
		refreshToken: string
	): Promise<SSOTokenResponse> {
		// Mock implementation
		if (refreshToken === 'test-refresh-token') {
			return {
				access_token: 'new-access-token',
				refresh_token: 'new-refresh-token',
				expires_in: 3600,
				token_type: 'Bearer',
			};
		}
		throw new Error('Invalid refresh token');
	}
}

describe('Authentication - SSO', () => {
	const db = createDatabase('authentication-sso');

	const auth = new TestSSOAuthentication({
		db,
		provider: 'test-provider',
	});

	beforeAll(async () => {
		await db.init();
		// Run parent migrations first
		await runMigrations(db, new AuthMigrations());
		// Run driver-specific migrations
		const migrationPack = new AuthenticationSSOMigrations();
		await getMigrations(db, migrationPack);
		await runMigrations(db, migrationPack);
	});

	afterAll(async () => {
		await db.disconnect();
	});

	describe('authenticate', () => {
		// eslint-disable-next-line max-len
		it('should create a new principal on first SSO authentication', async () => {
			const principal = await auth.authenticate({
				code: 'valid-code',
			});

			expect(principal).not.toBeNull();
			expect(principal?.login).toEqual('testuser@example.com');
			expect(principal?.name).toEqual('Test User');
			expect(principal?.type).toEqual('user');
		});

		// eslint-disable-next-line max-len
		it('should return existing principal on subsequent authentication', async () => {
			// First authentication - creates principal
			const firstAuth = await auth.authenticate({
				code: 'valid-code',
			});

			expect(firstAuth).not.toBeNull();
			const firstId = firstAuth?.id;

			// Second authentication with same code
			const secondAuth = await auth.authenticate({
				code: 'valid-code',
			});

			expect(secondAuth).not.toBeNull();
			expect(secondAuth?.id).toEqual(firstId);
		});

		it('should fail with invalid authorization code', async () => {
			let error: Error | undefined;

			try {
				await auth.authenticate({
					code: 'invalid-code',
				});
			}
			catch (err) {
				error = err as Error;
			}

			expect(error).toBeDefined();
			expect(error?.message).toContain('Invalid authorization code');
		});

		// eslint-disable-next-line max-len
		it('should save SSO tokens after successful authentication', async () => {
			const principal = await auth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			const token = await auth.getStoredToken(principal.id);

			expect(token).not.toBeNull();
			expect(token?.access_token).toEqual('test-access-token');
			expect(token?.refresh_token).toEqual('test-refresh-token');
			expect(token?.provider).toEqual('test-provider');
			expect(token?.provider_id).toEqual('provider-user-123');
		});

		// eslint-disable-next-line max-len
		it('should update existing SSO token on re-authentication', async () => {
			const principal = await auth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			const firstToken = await auth.getStoredToken(principal.id);
			const firstTokenId = firstToken?.id;

			// Re-authenticate
			await auth.authenticate({
				code: 'valid-code',
			});

			const secondToken = await auth.getStoredToken(principal.id);

			expect(secondToken?.id).toEqual(firstTokenId);
			expect(secondToken?.access_token).toEqual('test-access-token');
		});
	});

	describe('refreshAccessToken', () => {
		it('should refresh access token using refresh token', async () => {
			const principal = await auth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			const newAccessToken = await auth.refreshAccessToken(principal.id);

			expect(newAccessToken).toEqual('new-access-token');
		});

		// eslint-disable-next-line max-len
		it('should update stored token with new values after refresh', async () => {
			const principal = await auth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			await auth.refreshAccessToken(principal.id);

			const token = await auth.getStoredToken(principal.id);

			expect(token?.access_token).toEqual('new-access-token');
			expect(token?.refresh_token).toEqual('new-refresh-token');
		});

		it('should return null if refresh token does not exist', async () => {
			const principal = await auth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			// Create a principal without tokens
			const newPrincipalId = await auth.createPrincipal({
				login: 'no-tokens@example.com',
				name: 'No Tokens User',
				type: 'user',
			});

			const result = await auth.refreshAccessToken(newPrincipalId);

			expect(result).toBeNull();
		});
	});

	describe('getStoredToken', () => {
		it('should retrieve stored SSO token by principal ID', async () => {
			const principal = await auth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			const token = await auth.getStoredToken(principal.id);

			expect(token).not.toBeNull();
			expect(token?.principal_id).toEqual(principal.id);
			expect(token?.provider).toEqual('test-provider');
		});

		it('should return null for principal without SSO tokens', async () => {
			const principalId = await auth.createPrincipal({
				login: 'no-sso-tokens@example.com',
				name: 'No SSO User',
				type: 'user',
			});

			const token = await auth.getStoredToken(principalId);

			expect(token).toBeNull();
		});
	});

	describe('revokeSession', () => {
		it('should delete SSO tokens for a principal', async () => {
			const principal = await auth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			// Verify token exists
			let token = await auth.getStoredToken(principal.id);
			expect(token).not.toBeNull();

			// Revoke session
			await auth.revokeSession(principal.id);

			// Verify token is deleted
			token = await auth.getStoredToken(principal.id);
			expect(token).toBeNull();
		});

		// eslint-disable-next-line max-len
		it('should allow re-authentication after session revocation', async () => {
			const principal = await auth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			// Revoke session
			await auth.revokeSession(principal.id);

			// Re-authenticate
			const reAuthPrincipal = await auth.authenticate({
				code: 'valid-code',
			});

			expect(reAuthPrincipal).not.toBeNull();
			expect(reAuthPrincipal?.id).toEqual(principal.id);

			// Verify new token was created
			const newToken = await auth.getStoredToken(principal.id);
			expect(newToken).not.toBeNull();
		});
	});

	describe('getAuthorizationUrl', () => {
		it('should generate valid authorization URL', () => {
			const url = auth.getAuthorizationUrl('test-state-123');

			expect(url).toContain('https://provider.example.com/authorize');
			expect(url).toContain('state=test-state-123');
		});

		it('should include unique state in authorization URL', () => {
			const state1 = 'unique-state-1';
			const state2 = 'unique-state-2';

			const url1 = auth.getAuthorizationUrl(state1);
			const url2 = auth.getAuthorizationUrl(state2);

			expect(url1).toContain(state1);
			expect(url2).toContain(state2);
			expect(url1).not.toEqual(url2);
		});
	});

	describe('token expiration', () => {
		// eslint-disable-next-line max-len
		it('should set token expiration based on expires_in value', async () => {
			const principal = await auth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			const token = await auth.getStoredToken(principal.id);

			expect(token?.expires_at).toBeDefined();
			const expirationTime = token?.expires_at?.getTime() || 0;
			const now = Date.now();
			const timeDifference = expirationTime - now;

			// Should be approx 3600 seconds (1 hour) in future
			// Allow 5 second margin for test execution time
			expect(timeDifference).toBeGreaterThan(3595000);
			expect(timeDifference).toBeLessThan(3605000);
		});

		it('should update expiration time on token refresh', async () => {
			const principal = await auth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			const firstToken = await auth.getStoredToken(principal.id);
			const firstExpiration = firstToken?.expires_at?.getTime() || 0;

			// Wait a moment then refresh
			await new Promise((resolve) => setTimeout(resolve, 100));
			await auth.refreshAccessToken(principal.id);

			const secondToken = await auth.getStoredToken(principal.id);
			const secondExpiration = secondToken?.expires_at?.getTime() || 0;

			expect(secondExpiration).toBeGreaterThan(firstExpiration);
		});
	});

	describe('provider metadata', () => {
		// eslint-disable-next-line max-len
		it('should store provider-specific user information in metadata', async () => {
			const principal = await auth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			const token = await auth.getStoredToken(principal.id);

			expect(token?.provider_metadata).toBeDefined();
			const metadata = JSON.parse(token?.provider_metadata || '{}');

			expect(metadata.id).toEqual('provider-user-123');
			expect(metadata.login).toEqual('testuser@example.com');
			expect(metadata.name).toEqual('Test User');
		});
	});

	describe('multiple principals', () => {
		// eslint-disable-next-line max-len
		it(// eslint-disable-next-line max-len
			'should handle authentication for different principals independently', async () => {
				class MultiProviderSSO extends SSOAuthentication<SSOPrincipal> {
					private userIdCounter = 1;

					getAuthorizationUrl(state: string): string {
					// eslint-disable-next-line max-len
						return `https://provider.example.com/authorize?state=${state}`;
					}

					protected getAuthorizationParams(
						state: string
					): Record<string, string> {
						return {
							client_id: 'test-client-id',
							redirect_uri: 'http://localhost:3000/callback',
							scope: 'openid profile email',
							state,
						};
					}

					async exchangeAuthorizationCode(
						code: string
					): Promise<SSOTokenResponse> {
						if (code.startsWith('valid-')) {
							const userId = this.userIdCounter++;
							return {
								access_token: `access-${userId}`,
								refresh_token: `refresh-${userId}`,
								expires_in: 3600,
								token_type: 'Bearer',
							};
						}
						throw new Error('Invalid code');
					}

					protected async getUserInfo(
						accessToken: string
					): Promise<SSOUserInfo> {
						const userId = accessToken.split('-')[1];
						return {
							id: `provider-user-${userId}`,
							login: `user${userId}@example.com`,
							name: `User ${userId}`,
							type: 'user',
						};
					}

					protected async exchangeRefreshToken(
						refreshToken: string
					): Promise<SSOTokenResponse> {
						const userId = refreshToken.split('-')[1];
						return {
							access_token: `new-access-${userId}`,
							refresh_token: `new-refresh-${userId}`,
							expires_in: 3600,
							token_type: 'Bearer',
						};
					}
				}

				const multiAuth = new MultiProviderSSO({
					db,
					provider: 'test-provider',
				});

				const principal1 = await multiAuth.authenticate({
					code: 'valid-code-1',
				});
				const principal2 = await multiAuth.authenticate({
					code: 'valid-code-2',
				});

				expect(principal1).not.toBeNull();
				expect(principal2).not.toBeNull();
				expect(principal1?.id).not.toEqual(principal2?.id);
				expect(principal1?.login).toEqual('user1@example.com');
				expect(principal2?.login).toEqual('user2@example.com');

				// eslint-disable-next-line max-len
				const token1 = await multiAuth.getStoredToken(principal1?.id || '');
				// eslint-disable-next-line max-len
				const token2 = await multiAuth.getStoredToken(principal2?.id || '');

				expect(token1?.provider_id).toEqual('provider-user-1');
				expect(token2?.provider_id).toEqual('provider-user-2');
			});
	});

	describe('CSRF protection - state validation', () => {
		// eslint-disable-next-line max-len
		it('should generate unique state for each authorization request', async () => {
			const state1 = await auth.generateState();
			const state2 = await auth.generateState();

			expect(state1).toBeDefined();
			expect(state2).toBeDefined();
			expect(state1.length).toBeGreaterThan(16);
			expect(state2.length).toBeGreaterThan(16);
			expect(state1).not.toEqual(state2);
		});

		// eslint-disable-next-line max-len
		it('should store state with correct expiration time', async () => {
			const state = await auth.generateState();
			const storedState = await auth.getStoredState(state);

			expect(storedState).not.toBeNull();
			expect(storedState?.state).toEqual(state);
			expect(storedState?.provider).toEqual('test-provider');
			expect(storedState?.expires_at).toBeDefined();

			const expirationTime = storedState?.expires_at.getTime() || 0;
			const now = Date.now();
			const timeDifference = expirationTime - now;

			// Should be approximately 10 minutes (600000 ms) in future
			expect(timeDifference).toBeGreaterThan(595000);
			expect(timeDifference).toBeLessThan(605000);
		});

		it('should validate matching state parameter', async () => {
			const state = await auth.generateState();

			const isValid = await auth.validateState(state);

			expect(isValid).toBe(true);
		});

		it('should reject mismatched state', async () => {
			let error: Error | undefined;

			try {
				await auth.validateState('invalid-state-value');
			}
			catch (err) {
				error = err as Error;
			}

			expect(error).toBeDefined();
			expect(error?.message).toContain('State validation failed');
		});

		// eslint-disable-next-line max-len
		it('should reject reused/consumed state parameters', async () => {
			const state = await auth.generateState();

			// First use - should succeed
			await auth.validateState(state);

			// Second use - should fail (state consumed)
			let error: Error | undefined;

			try {
				await auth.validateState(state);
			}
			catch (err) {
				error = err as Error;
			}

			expect(error).toBeDefined();
			expect(error?.message).toContain('State has been consumed');
		});

		// eslint-disable-next-line max-len
		it('should authenticate with valid state parameter', async () => {
			const state = await auth.generateState();
			const principal = await auth.authenticate({
				code: 'valid-code',
				state,
			});

			expect(principal).not.toBeNull();
			expect(principal?.login).toEqual('testuser@example.com');
		});

		// eslint-disable-next-line max-len
		it('should reject authentication with mismatched state', async () => {
			let error: Error | undefined;

			try {
				await auth.authenticate({
					code: 'valid-code',
					state: 'wrong-state',
				});
			}
			catch (err) {
				error = err as Error;
			}

			expect(error).toBeDefined();
			expect(error?.message).toContain('State validation failed');
		});

		// eslint-disable-next-line max-len
		it('should allow authentication without state (backward compatibility)', async () => {
			const principal = await auth.authenticate({
				code: 'valid-code',
			});

			expect(principal).not.toBeNull();
			expect(principal?.login).toEqual('testuser@example.com');
		});

		// eslint-disable-next-line max-len
		it('should generate authorization URL with embedded state', async () => {
			const result = await auth.generateAuthorizationUrl();

			expect(result.url).toBeDefined();
			expect(result.state).toBeDefined();
			expect(result.url).toContain(result.state);
			expect(result.url).toContain(
				'https://provider.example.com/authorize'
			);
		});

		// eslint-disable-next-line max-len
		it('should generate unique URLs for each authorization request', async () => {
			const result1 = await auth.generateAuthorizationUrl();
			const result2 = await auth.generateAuthorizationUrl();

			expect(result1.url).not.toEqual(result2.url);
			expect(result1.state).not.toEqual(result2.state);
		});

		// eslint-disable-next-line max-len
		it('should cleanup expired state records', async () => {
			const state = await auth.generateState();
			const storedStateBefore = await auth.getStoredState(state);

			expect(storedStateBefore).not.toBeNull();

			// Cleanup should not delete non-expired states
			await auth.cleanupExpiredStates();

			const storedStateAfter = await auth.getStoredState(state);
			expect(storedStateAfter).not.toBeNull();
		});
	});

	describe('Token Encryption', () => {
		let encryptedAuth: TestSSOAuthentication;

		beforeAll(async () => {
			// Generate encryption keys
			const generator = new KeyPairGenerator({ algorithm: 'RS256' });
			const keypair = generator.generate();

			// Create auth with encryption enabled
			encryptedAuth = new TestSSOAuthentication({
				db,
				provider: 'test-provider-encrypted',
				encryptionPublicKey: keypair.publicKey,
				encryptionPrivateKey: keypair.privateKey,
			});
		});

		it('should encrypt tokens before storing in database', async () => {
			const principal = await encryptedAuth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			// Get the raw record from database (without decryption)
			const rawRecord = await encryptedAuth['ssoTokenRepo'].findOne({
				where: {
					principal_id: principal.id,
					provider: 'test-provider-encrypted',
				},
			});

			expect(rawRecord).not.toBeNull();
			// Encrypted tokens should be base64 strings, not plaintext
			expect(rawRecord?.access_token).not.toEqual('test-access-token');
			expect(rawRecord?.refresh_token).not.toEqual('test-refresh-token');
			// They should be valid base64
			// eslint-disable-next-line max-len
			expect(() =>
				Buffer.from(rawRecord!.access_token, 'base64')
			).not.toThrow();
			// eslint-disable-next-line max-len
			expect(() =>
				Buffer.from(rawRecord!.refresh_token!, 'base64')
			).not.toThrow();
		});

		it('should decrypt tokens when retrieving from database', async () => {
			const principal = await encryptedAuth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			const decrypted = await encryptedAuth.getStoredToken(principal.id);

			expect(decrypted).not.toBeNull();
			// Decrypted tokens should match the original plaintext
			expect(decrypted?.access_token).toEqual('test-access-token');
			expect(decrypted?.refresh_token).toEqual('test-refresh-token');
		});

		// eslint-disable-next-line max-len
		it('should encrypt new tokens on refresh with encryption', async () => {
			const principal = await encryptedAuth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			// Refresh the token
			await encryptedAuth.refreshAccessToken(principal.id);

			// Get the raw record from database
			const rawRecord = await encryptedAuth['ssoTokenRepo'].findOne({
				where: {
					principal_id: principal.id,
					provider: 'test-provider-encrypted',
				},
			});

			expect(rawRecord).not.toBeNull();
			// New tokens should also be encrypted
			expect(rawRecord?.access_token).not.toEqual('new-access-token');
			expect(rawRecord?.refresh_token).not.toEqual('new-refresh-token');
		});

		// eslint-disable-next-line max-len
		// eslint-disable-next-line max-len
		it('should decrypt refresh token before using it', async () => {
			const principal = await encryptedAuth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			// Refresh should work correctly even with encrypted tokens
			// eslint-disable-next-line max-len
			const newToken = await encryptedAuth.refreshAccessToken(
				principal.id
			);

			expect(newToken).not.toBeNull();
			// Returned token should be encrypted (base64)
			expect(() => Buffer.from(newToken!, 'base64')).not.toThrow();
		});

		// eslint-disable-next-line max-len
		it('should decrypt refresh token to access new token', async () => {
			const principal = await encryptedAuth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			// Refresh the token
			await encryptedAuth.refreshAccessToken(principal.id);

			// Get decrypted token
			const decrypted = await encryptedAuth.getStoredToken(principal.id);

			expect(decrypted?.access_token).toEqual('new-access-token');
			expect(decrypted?.refresh_token).toEqual('new-refresh-token');
		});

		// eslint-disable-next-line max-len
		it('should handle different data for access and refresh tokens', async () => {
			const principal = await encryptedAuth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			const rawRecord = await encryptedAuth['ssoTokenRepo'].findOne({
				where: {
					principal_id: principal.id,
					provider: 'test-provider-encrypted',
				},
			});

			expect(rawRecord).not.toBeNull();
			// Encrypted values should be different (due to RSA random padding)
			// eslint-disable-next-line max-len
			expect(rawRecord?.access_token).not.toEqual(
				rawRecord?.refresh_token
			);
		});

		// eslint-disable-next-line max-len
		it('should support revokeSession with encryption enabled', async () => {
			const principal = await encryptedAuth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			// Verify token exists
			let token = await encryptedAuth.getStoredToken(principal.id);
			expect(token).not.toBeNull();

			// Revoke session
			await encryptedAuth.revokeSession(principal.id);

			// Verify token is deleted
			token = await encryptedAuth.getStoredToken(principal.id);
			expect(token).toBeNull();
		});

		// eslint-disable-next-line max-len
		it('should not decrypt if decryptor is not configured', async () => {
			// Create auth with only encryptor, no decryptor
			const generator = new KeyPairGenerator({ algorithm: 'RS256' });
			const keypair = generator.generate();

			const partialAuth = new TestSSOAuthentication({
				db,
				provider: 'test-provider-partial',
				encryptionPublicKey: keypair.publicKey,
				// No encryptionPrivateKey
			});

			const principal = await partialAuth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			// Get the raw encrypted record
			const rawRecord = await partialAuth['ssoTokenRepo'].findOne({
				where: {
					principal_id: principal.id,
					provider: 'test-provider-partial',
				},
			});

			expect(rawRecord).not.toBeNull();
			// Token is encrypted in DB
			expect(rawRecord?.access_token).not.toEqual('test-access-token');

			// getStoredToken returns encrypted data (since no decryptor)
			const token = await partialAuth.getStoredToken(principal.id);
			expect(token?.access_token).toEqual(rawRecord?.access_token);
		});

		// eslint-disable-next-line max-len
		it('should handle null refresh token gracefully with encryption', async () => {
			const generator = new KeyPairGenerator({ algorithm: 'RS256' });
			const keypair = generator.generate();

			const encAuth = new TestSSOAuthentication({
				db,
				provider: 'test-provider-no-refresh',
				encryptionPublicKey: keypair.publicKey,
				encryptionPrivateKey: keypair.privateKey,
			});

			const principal = await encAuth.authenticate({
				code: 'valid-code',
			});

			if (!principal) {
				throw new Error('Authentication failed');
			}

			// Manually update to remove refresh token
			const rawRecord = await encAuth['ssoTokenRepo'].findOne({
				where: {
					principal_id: principal.id,
					provider: 'test-provider-no-refresh',
				},
			});

			await encAuth['ssoTokenRepo'].update({
				set: { refresh_token: undefined },
				where: { id: rawRecord?.id },
			});

			// Should return null without throwing
			const result = await encAuth.refreshAccessToken(principal.id);
			expect(result).toBeNull();
		});
	});
});
