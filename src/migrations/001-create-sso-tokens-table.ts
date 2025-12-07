import { ColumnType } from '@riao/dbal';
import { CreateTimestampColumn, UUIDKeyColumn } from '@riao/dbal/column-pack';
import { Migration } from '@riao/dbal';

/**
 * Create SSO tokens table for storing OAuth2/OIDC provider
 * tokens and user mappings
 */
export class CreateSSOTokensTable extends Migration {
	override async up(): Promise<void> {
		await this.ddl.createTable({
			name: 'iam_sso_tokens',
			columns: [
				UUIDKeyColumn,
				{
					name: 'principal_id',
					type: ColumnType.UUID,
					required: true,
					fk: {
						referencesTable: 'iam_principals',
						referencesColumn: 'id',
						onDelete: 'CASCADE',
					},
				},
				{
					name: 'provider',
					type: ColumnType.VARCHAR,
					length: 50,
					required: true,
				},
				{
					name: 'provider_id',
					type: ColumnType.VARCHAR,
					length: 255,
					required: true,
				},
				{
					name: 'access_token',
					type: ColumnType.TEXT,
					required: true,
				},
				{
					name: 'refresh_token',
					type: ColumnType.TEXT,
				},
				{
					name: 'expires_at',
					type: ColumnType.TIMESTAMP,
					required: true,
				},
				{
					name: 'provider_metadata',
					type: ColumnType.TEXT,
				},
				CreateTimestampColumn,
			],
		});
	}

	override async down(): Promise<void> {
		await this.ddl.dropTable({ tables: ['iam_sso_tokens'] });
	}
}
