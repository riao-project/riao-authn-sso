import {
	ProviderAuthenticationRejectedError,
	throwProviderResponseError,
} from '../../src/provider-response';

describe('SSO provider rejection classification', () => {
	it('classifies known credential rejections without provider details', async () => {
		const response = new Response(JSON.stringify({
			error: 'invalid_grant',
			error_description: 'secret-token',
		}), { status: 400 });

		await expectAsync(throwProviderResponseError(
			'Token exchange', response
		)).toBeRejectedWithError(ProviderAuthenticationRejectedError);
	});

	it('keeps outages and throttling operational without response details', async () => {
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

	it('classifies a provider user-info 401 as credential rejection', async () => {
		const response = new Response('secret-token', { status: 401 });

		await expectAsync(throwProviderResponseError(
			'User info', response, true
		)).toBeRejectedWithError(ProviderAuthenticationRejectedError);
	});
});
