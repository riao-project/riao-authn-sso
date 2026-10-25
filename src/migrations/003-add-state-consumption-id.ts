import { ColumnType, Migration } from '@riao/dbal';

export class AddStateConsumptionId extends Migration {
	override async up(): Promise<void> {
		await this.ddl.addColumns({
			table: 'iam_sso_state',
			columns: [{
				name: 'consumption_id',
				type: ColumnType.VARCHAR,
				length: 64,
			}],
		});
	}

	override async down(): Promise<void> {
		await this.ddl.dropColumn({
			table: 'iam_sso_state',
			column: 'consumption_id',
		});
	}
}
