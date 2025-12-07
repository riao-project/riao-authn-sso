import { Migration, MigrationPackage } from '@riao/dbal';
import { CreateSSOTokensTable } from './migrations/001-create-sso-tokens-table';

export class AuthenticationSSOMigrations extends MigrationPackage {
	override package = '@riao/authn-sso';
	override name = '@riao/authn-sso';

	override async getMigrations(): Promise<
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		Record<string, typeof Migration<any>>
		> {
		return {
			'create-sso-tokens-table': CreateSSOTokensTable,
		};
	}
}
