import {
	ProviderAuthenticationRejectedError,
	requestProviderJson,
	throwProviderResponseError,
	validateProviderUser,
	validateTokenResponse,
} from '../../src/provider-response';

describe('SSO provider response helpers', () => {
	it('adds a timeout signal to provider requests', async () => {
		const timeoutSpy = spyOn(AbortSignal, 'timeout').and.callThrough();
		const fetchSpy = spyOn(global, 'fetch').and.resolveTo(
			new Response(JSON.stringify({ access_token: 'token' }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			})
		);

		await requestProviderJson(
			'https://provider.example/token',
			{},
			'Token exchange',
			250
		);

		const request = fetchSpy.calls.mostRecent().args[1];
		expect(request?.signal).toBeDefined();
		expect(timeoutSpy).toHaveBeenCalledWith(250);
	});

	it('does not expose provider response bodies in errors', async () => {
		spyOn(global, 'fetch').and.resolveTo(
			new Response(JSON.stringify({
				error: 'invalid_grant',
				error_description: 'secret-token-value',
			}), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			})
		);

		let error: Error | undefined;
		try {
			await requestProviderJson(
				'https://provider.example/token',
				{},
				'Token exchange',
				250
			);
		}
		catch (caught) {
			error = caught as Error;
		}

		expect(error).toEqual(jasmine.any(ProviderAuthenticationRejectedError));
		expect(error?.message).not.toContain('secret-token-value');
	});

	it(
		'classifies expected rejections separately from operational failures',
		async () => {
			const fetchSpy = spyOn(global, 'fetch').and.resolveTo(
				new Response(JSON.stringify({ error: 'access_denied' }), {
					status: 400,
					headers: { 'Content-Type': 'application/json' },
				})
			);
			await expectAsync(requestProviderJson(
				'https://provider.example/token',
				{},
				'Token exchange',
				250
			)).toBeRejectedWith(
				jasmine.any(ProviderAuthenticationRejectedError)
			);

			const transportError = new Error('secret transport detail');
			fetchSpy.and.rejectWith(transportError);
			let error: Error | undefined;
			try {
				await requestProviderJson(
					'https://provider.example/token',
					{},
					'Token exchange',
					250
				);
			}
			catch (caught) {
				error = caught as Error;
			}
			expect(error?.message).not.toContain('secret transport detail');
			expect(error?.cause).toBe(transportError);
		}
	);

	it('rejects malformed token and user responses', () => {
		expect(() => validateTokenResponse({
			access_token: '',
			expires_in: Number.NaN,
		})).toThrowError('Malformed provider token response');
		expect(() => validateProviderUser({ id: 12 }, []))
			.toThrowError('Malformed provider user response');
	});

	it(
		'exposes response classification for baseline-compatible consumers',
		async () => {
			await expectAsync(throwProviderResponseError(
				'User info',
				new Response('secret-token', { status: 401 }),
				true
			)).toBeRejectedWith(
				jasmine.any(ProviderAuthenticationRejectedError)
			);
			await expectAsync(throwProviderResponseError(
				'Token exchange',
				new Response(JSON.stringify({
					error: 'invalid_client',
					error_description: 'secret-token',
				}), { status: 400 })
			)).toBeRejectedWithError('Token exchange failed: 400');
		}
	);
});
