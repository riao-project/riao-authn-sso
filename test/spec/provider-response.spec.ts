import {
	ProviderAuthenticationRejectedError,
	requestProviderJson,
	validateProviderUser,
	validateTokenResponse,
	throwProviderResponseError,
} from '../../src/provider-response';

describe('SSO provider rejection classification', () => {
	it('classifies credential rejections without details', async () => {
		const response = new Response(JSON.stringify({
			error: 'invalid_grant',
			error_description: 'secret-token',
		}), { status: 400 });

		await expectAsync(throwProviderResponseError(
			'Token exchange', response
		)).toBeRejectedWithError(ProviderAuthenticationRejectedError);
	});

	it('keeps outages/throttling operational without details', async () => {
		for (const status of [429, 503]) {
			const response = new Response(JSON.stringify({
				error: 'invalid_grant',
				error_description: 'secret-token',
			}), { status });

			try {
				await throwProviderResponseError('Token exchange', response);
				fail('Expected operational provider error');
			}
			catch (error) {
				expect(error).not.toEqual(
					jasmine.any(ProviderAuthenticationRejectedError)
				);
				expect((error as Error).message).not.toContain('secret-token');
			}
		}
	});

	it('classifies user-info 401 as credential rejection', async () => {
		const response = new Response('secret-token', { status: 401 });

		await expectAsync(throwProviderResponseError(
			'User info', response, true
		)).toBeRejectedWithError(ProviderAuthenticationRejectedError);
	});
});

describe('SSO provider response helpers', () => {
	it('preserves an already-aborted caller signal', async () => {
		const controller = new AbortController();
		const reason = new Error('Caller cancelled');
		controller.abort(reason);
		spyOn(global, 'fetch').and.callFake(async (_url, options) => {
			expect(options?.signal?.aborted).toBe(true);
			expect(options?.signal?.reason).toBe(reason);
			options?.signal?.throwIfAborted();
			throw new Error('Expected an aborted request');
		});

		await expectAsync(requestProviderJson(
			'https://provider.example/token',
			{ signal: controller.signal },
			'Token exchange',
			250
		)).toBeRejectedWith(jasmine.objectContaining({
			message: 'Token exchange failed: unavailable; ' +
				'provider unavailable or invalid JSON',
			cause: reason,
		}));
	});

	for (const source of ['caller', 'timeout']) {
		it(`cancels a pending request on ${source} abort`, async () => {
			const caller = new AbortController();
			const timeout = new AbortController();
			const reason = new Error(`${source} cancelled`);
			spyOn(AbortSignal, 'timeout').and.returnValue(timeout.signal);
			const fetchSpy = spyOn(global, 'fetch').and.callFake(
				async (_url, options) =>
					new Promise<Response>((_resolve, reject) => {
						options?.signal?.addEventListener('abort', () => {
							reject(options.signal?.reason);
						}, { once: true });
					})
			);

			const request = requestProviderJson(
				'https://provider.example/token',
				{ signal: caller.signal },
				'Token exchange',
				250
			);
			expect(fetchSpy).toHaveBeenCalledTimes(1);
			(source === 'caller' ? caller : timeout).abort(reason);

			await expectAsync(request).toBeRejectedWith(
				jasmine.objectContaining({
					message: 'Token exchange failed: unavailable; ' +
						'provider unavailable or invalid JSON',
					cause: reason,
				})
			);
		});
	}

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
