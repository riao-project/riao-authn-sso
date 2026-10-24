export class ProviderAuthenticationRejectedError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'ProviderAuthenticationRejectedError';
	}
}

function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null &&
		!Array.isArray(value);
}

export async function throwProviderResponseError(
	operation: string,
	response: Response,
	userInfo = false
): Promise<never> {
	let data: unknown;
	try {
		data = await response.json();
	}
	catch {
		data = undefined;
	}

	const providerError = isObject(data) ? data['error'] : undefined;
	const code = isObject(providerError)
		? providerError['code']
		: providerError;
	const rejectedCodes = [
		'invalid_grant',
		'invalid_token',
		'invalid_code',
		'access_denied',
		'interaction_required',
		'login_required',
		'consent_required',
		'InvalidAuthenticationToken',
	];
	const rejected = (
		userInfo && response.status === 401
	) || (
		response.status >= 400 && response.status < 500 &&
		response.status !== 408 && response.status !== 429 &&
		typeof code === 'string' && rejectedCodes.includes(code)
	);
	if (rejected) {
		throw new ProviderAuthenticationRejectedError(
			`${operation} failed: ${response.status}`
		);
	}

	throw new Error(`${operation} failed: ${response.status}`);
}
