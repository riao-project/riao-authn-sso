import { ColumnType } from '@riao/dbal';
import { CreateTimestampColumn } from '@riao/dbal/column-pack';
import { Migration } from '@riao/dbal';

/**
 * Create SSO state table for storing OAuth2/OIDC state parameters
 * used for CSRF protection
 */
export class CreateSSOStateTable extends Migration {
	override async up(): Promise<void> {
		await this.ddl.createTable({
			name: 'iam_sso_state',
			columns: [
				{
					name: 'state',
					type: ColumnType.VARCHAR,
					length: 128,
					required: true,
					primaryKey: true,
				},
				{
					name: 'provider',
					type: ColumnType.VARCHAR,
					length: 50,
					required: true,
				},
				{
					name: 'principal_id',
					type: ColumnType.UUID,
					fk: {
						referencesTable: 'iam_principals',
						referencesColumn: 'id',
						onDelete: 'CASCADE',
					},
				},
				{
					name: 'created_at',
					type: ColumnType.TIMESTAMP,
					required: true,
				},
				{
					name: 'expires_at',
					type: ColumnType.TIMESTAMP,
					required: true,
				},
				{
					name: 'used_at',
					type: ColumnType.TIMESTAMP,
				},
				CreateTimestampColumn,
			],
		});

		await this.ddl.createIndex({
			table: 'iam_sso_state',
			name: 'idx_sso_state_expires_at',
			column: 'expires_at',
		});

		await this.ddl.createIndex({
			table: 'iam_sso_state',
			name: 'idx_sso_state_principal',
			column: 'principal_id',
		});
	}

	override async down(): Promise<void> {
		await this.ddl.dropTable({ tables: ['iam_sso_state'] });
	}
}
