import 'jasmine';
import { Database } from '@riao/dbal';
import { Principal } from '@riao/iam';
import {
	AuthenticationProtection,
	AuthenticationRejectedError,
	AuthenticationBlockedError,
} from '@riao/iam/authentication';
import {
	ProviderAuthenticationRejectedError,
	SSOAuthentication,
	SSOTokenResponse,
	SSOUserInfo,
} from '../../src';

class ContractSSO extends SSOAuthentication<Principal> {
	getAuthorizationUrl(state: string): string {
		return state;
	}
	protected getAuthorizationParams(): Record<string, string> {
		return {};
	}
	async exchangeAuthorizationCode(): Promise<SSOTokenResponse> {
		return { access_token: 'secret-token', expires_in: 3600 };
	}
	protected async getUserInfo(): Promise<SSOUserInfo> {
		return {
			id: 'provider-id', login: 'person@example.com',
			name: 'Person', type: 'user',
		};
	}
	protected async exchangeRefreshToken(): Promise<SSOTokenResponse> {
		return { access_token: 'secret-token', expires_in: 3600 };
	}
}

describe('SSO authentication contract (isolated)', () => {
	let auth: ContractSSO;
	let repo: jasmine.SpyObj<{
		findOne: () => Promise<unknown>;
		update: () => Promise<void>;
	}>;
	let protection: jasmine.SpyObj<AuthenticationProtection>;
	const principal: Principal = {
		id: 'principal-id', login: 'person@example.com', type: 'user',
		name: 'Person', create_timestamp: new Date(),
	};
	const credentials = { code: 'secret-code', state: 'secret-state' };

	beforeEach(() => {
		repo = jasmine.createSpyObj('repository', ['findOne', 'update']);
		repo.findOne.and.resolveTo(principal);
		repo.update.and.resolveTo();
		const db = {
			getQueryRepository: () => repo,
		} as unknown as Database;
		protection = jasmine.createSpyObj('protection', [
			'beforeAttempt', 'onFailure', 'onSuccess',
		]);
		protection.beforeAttempt.and.resolveTo({ allowed: true });
		protection.onFailure.and.resolveTo();
		protection.onSuccess.and.resolveTo();
		auth = new ContractSSO({
			db, provider: 'test', authenticationProtection: protection,
		});
		spyOn(auth, 'validateState').and.resolveTo(true);
		spyOn(auth, 'findActivePrincipal').and.resolveTo(principal as Principal);
		spyOn(auth, 'createPrincipal').and.resolveTo('new-id');
		spyOn(auth, 'exchangeAuthorizationCode').and.callThrough();
		spyOn(auth, 'saveTokens' as never).and.resolveTo();
	});

	it('denies before provider or state work without recording an outcome', async () => {
		protection.beforeAttempt.and.resolveTo({ allowed: false });
		expect(await auth.authenticate(credentials)).toBeNull();
		expect(auth.validateState).not.toHaveBeenCalled();
		expect(auth.exchangeAuthorizationCode).not.toHaveBeenCalled();
		expect(protection.onFailure).not.toHaveBeenCalled();
		expect(protection.onSuccess).not.toHaveBeenCalled();
	});

	it('records success once after saving tokens without exposing credentials', async () => {
		expect(await auth.authenticate(credentials)).toEqual(principal);
		expect(protection.onSuccess).toHaveBeenCalledTimes(1);
		expect(protection.onFailure).not.toHaveBeenCalled();
		expect(protection.onSuccess).toHaveBeenCalledWith({
			scheme: 'sso:test', subject: 'test',
		});
		expect(auth.validateState).toHaveBeenCalledBefore(
			auth.exchangeAuthorizationCode as jasmine.Spy
		);
		expect(auth['saveTokens'] as jasmine.Spy).toHaveBeenCalledBefore(
			protection.onSuccess
		);
	});

	it('records expected provider rejection once', async () => {
		(auth.exchangeAuthorizationCode as jasmine.Spy).and.rejectWith(
			new AuthenticationRejectedError('Rejected')
		);
		expect(await auth.authenticate(credentials)).toBeNull();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
		expect(protection.onSuccess).not.toHaveBeenCalled();
	});

	it('records shared provider-helper rejection once', async () => {
		(auth.exchangeAuthorizationCode as jasmine.Spy).and.rejectWith(
			new ProviderAuthenticationRejectedError('Rejected')
		);
		expect(await auth.authenticate(credentials)).toBeNull();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
		expect(protection.onSuccess).not.toHaveBeenCalled();
	});

	it('does not count blocked provider attempts', async () => {
		(auth.exchangeAuthorizationCode as jasmine.Spy).and.rejectWith(
			new AuthenticationBlockedError(60)
		);
		expect(await auth.authenticate(credentials)).toBeNull();
		expect(protection.onFailure).not.toHaveBeenCalled();
	});

	it('propagates provider outages without failure callbacks', async () => {
		const outage = new Error('Outage');
		(auth.exchangeAuthorizationCode as jasmine.Spy).and.rejectWith(outage);
		await expectAsync(auth.authenticate(credentials)).toBeRejectedWith(outage);
		expect(protection.onFailure).not.toHaveBeenCalled();
	});

	it('propagates storage errors without recording failure', async () => {
		const outage = new Error('Database unavailable');
		repo.findOne.and.rejectWith(outage);
		await expectAsync(auth.authenticate(credentials)).toBeRejectedWith(outage);
		expect(protection.onFailure).not.toHaveBeenCalled();
	});

	it('rejects missing code before exchange', async () => {
		for (const input of [{ code: '' }, undefined]) {
			expect(await auth.authenticate(input as typeof credentials)).toBeNull();
		}
		expect(protection.onFailure).toHaveBeenCalledTimes(2);
		expect(auth.exchangeAuthorizationCode).not.toHaveBeenCalled();
	});

	it('rejects callbacks without state before exchange', async () => {
		const input = { code: 'secret-code' } as typeof credentials;
		expect(await auth.authenticate(input)).toBeNull();
		expect(auth.validateState).not.toHaveBeenCalled();
		expect(auth.exchangeAuthorizationCode).not.toHaveBeenCalled();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
	});

	it('rejects an empty state before exchange', async () => {
		expect(await auth.authenticate({
			code: 'secret-code',
			state: '',
		})).toBeNull();
		expect(auth.exchangeAuthorizationCode).not.toHaveBeenCalled();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
	});

	it('records invalid, expired and replayed state as rejection', async () => {
		for (const message of ['Invalid state', 'Expired state', 'Replayed state']) {
			(auth.validateState as jasmine.Spy).and.rejectWith(
				new AuthenticationRejectedError(message)
			);
			expect(await auth.authenticate(credentials)).toBeNull();
		}
		expect(protection.onFailure).toHaveBeenCalledTimes(3);
		expect(auth.exchangeAuthorizationCode).not.toHaveBeenCalled();
	});

	it('propagates state database failure without counting rejection', async () => {
		const outage = new Error('State database unavailable');
		(auth.validateState as jasmine.Spy).and.rejectWith(outage);
		await expectAsync(auth.authenticate(credentials)).toBeRejectedWith(outage);
		expect(protection.onFailure).not.toHaveBeenCalled();
	});

	it('does not provision a replacement for an inactive principal', async () => {
		(auth.findActivePrincipal as jasmine.Spy).and.resolveTo(null);
		expect(await auth.authenticate(credentials)).toBeNull();
		expect(auth.createPrincipal).not.toHaveBeenCalled();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
	});

	it('provisions only when the principal is absent', async () => {
		repo.findOne.and.resolveTo(null);
		expect(await auth.authenticate(credentials)).toEqual(principal);
		expect(auth.createPrincipal).toHaveBeenCalledTimes(1);
		expect(protection.onSuccess).toHaveBeenCalledTimes(1);
	});

	it('propagates a miss resolving a newly created principal operationally', async () => {
		repo.findOne.and.resolveTo(null);
		(auth.findActivePrincipal as jasmine.Spy).and.resolveTo(null);

		await expectAsync(auth.authenticate(credentials))
			.toBeRejectedWithError(
				'Unable to resolve newly created SSO principal'
			);
		expect(protection.onFailure).not.toHaveBeenCalled();
		expect(protection.onSuccess).not.toHaveBeenCalled();
	});

	it('propagates callback failures without calling failure for success errors', async () => {
		const outage = new Error('Protection storage unavailable');
		protection.onSuccess.and.rejectWith(outage);
		await expectAsync(auth.authenticate(credentials)).toBeRejectedWith(outage);
		expect(protection.onFailure).not.toHaveBeenCalled();
	});
});
