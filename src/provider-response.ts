import { SSOTokenResponse } from './sso-config';

export class ProviderAuthenticationRejectedError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'ProviderAuthenticationRejectedError';
	}
}

export function isProviderObject(
	value: unknown
): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isProviderString(value: unknown): value is string {
	return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Fetch and decode a provider response without exposing its body or transport
 * error. Causes remain attached for trusted operational diagnostics.
 */
export async function requestProviderJson(
	url: string,
	options: RequestInit,
	operation: string,
	timeoutMs: number,
	userInfo = false
): Promise<Record<string, unknown>> {
	let response: Response | undefined;
	let data: unknown;
	try {
		response = await fetch(url, {
			...options,
			signal: AbortSignal.timeout(timeoutMs),
		});
		if (userInfo && response.status === 401) {
			throw new ProviderAuthenticationRejectedError(
				`${operation} failed: 401`
			);
		}
		data = await response.json();
	}
	catch (error) {
		if (error instanceof ProviderAuthenticationRejectedError) {
			throw error;
		}
		throw new Error(
			`${operation} failed: ${response?.status ?? 'unavailable'}; ` +
			'provider unavailable or invalid JSON',
			{ cause: error }
		);
	}

	if (!response.ok) {
		const providerError = isProviderObject(data)
			? data['error']
			: undefined;
		const code = isProviderObject(providerError)
			? providerError['code']
			: providerError;
		const rejections = [
			'invalid_grant',
			'invalid_token',
			'invalid_code',
			'access_denied',
			'interaction_required',
			'login_required',
			'consent_required',
			'InvalidAuthenticationToken',
		];
		if (
			response.status >= 400 && response.status < 500 &&
			response.status !== 408 && response.status !== 429 &&
			typeof code === 'string' && rejections.includes(code)
		) {
			throw new ProviderAuthenticationRejectedError(
				`${operation} failed: ${response.status}`
			);
		}
		throw new Error(`${operation} failed: ${response.status}`);
	}

	if (!isProviderObject(data)) {
		throw new Error(`${operation} failed: malformed response`);
	}
	return data;
}

export function validateTokenResponse(
	data: Record<string, unknown>
): SSOTokenResponse {
	if (
		!isProviderString(data['access_token']) ||
		typeof data['expires_in'] !== 'number' ||
		!Number.isFinite(data['expires_in']) || data['expires_in'] <= 0 ||
		(data['refresh_token'] !== undefined &&
			!isProviderString(data['refresh_token'])) ||
		(data['token_type'] !== undefined &&
			!isProviderString(data['token_type']))
	) {
		throw new Error('Malformed provider token response');
	}
	return data as SSOTokenResponse;
}

export function validateProviderUser(
	data: Record<string, unknown>,
	optionalFields: string[],
	allowNull = false
): void {
	if (
		!isProviderString(data['id']) ||
		optionalFields.some((field) =>
			data[field] !== undefined && !(allowNull && data[field] === null) &&
			typeof data[field] !== 'string'
		)
	) {
		throw new Error('Malformed provider user response');
	}
}
