import { Migration, MigrationPackage } from '@riao/dbal';
import { CreateSSOTokensTable } from './migrations/001-create-sso-tokens-table';
import { CreateSSOStateTable } from './migrations/002-create-sso-state-table';
import {
	AddStateConsumptionId,
} from './migrations/003-add-state-consumption-id';

export class AuthenticationSSOMigrations extends MigrationPackage {
	override package = '@riao/authn-sso';
	override name = '@riao/authn-sso';

	override async getMigrations(): Promise<
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		Record<string, typeof Migration<any>>
		> {
		return {
			'create-sso-tokens-table': CreateSSOTokensTable,
			'create-sso-state-table': CreateSSOStateTable,
			'add-state-consumption-id': AddStateConsumptionId,
		};
	}
}
