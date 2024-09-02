import logging
import pylibinjection

from tanner.config import TannerConfig
from tanner.emulators import mysqli, sqlite

class SqliEmulator:
    def __init__(self, db_name, working_dir):
        self.logger = logging.getLogger("tanner.sqli_emulator")

        # Initialize the SQLi emulator based on the configured database type (MySQL or SQLite)
        if TannerConfig.get("SQLI", "type") == "MySQL":
            self.sqli_emulator = mysqli.MySQLIEmulator(db_name)
        else:
            self.sqli_emulator = sqlite.SQLITEEmulator(db_name, working_dir)

        self.query_map = None  # Placeholder for the database schema mapping

    def scan(self, value):
        """
        Scans the input value for SQL injection attempts using the pylibinjection library.
        """
        detection = None
        payload = bytes(value, "utf-8")
        sqli = pylibinjection.detect_sqli(payload)  # Detect SQLi using pylibinjection
        if int(sqli["sqli"]):
            # Logging added to track SQLi detection
            self.logger.info(f"SQLi detected: {value}")
            detection = dict(name="sqli", order=2)  # SQLi detected, returning with priority order 2
        return detection

    def map_query(self, attack_value):
        """
        Maps the SQLi attack parameters to a corresponding database query.
        """
        db_query = None
        param = attack_value["id"]
        param_value = attack_value["value"].replace("'", " ")  # Replace single quotes to prevent syntax errors
        tables = []

        # Map the parameters to the corresponding database table and column
        for table, columns in self.query_map.items():
            for column in columns:
                if param == column["name"]:
                    tables.append(dict(table_name=table, column=column))

        # Construct the database query based on the column type (INTEGER or other)
        if tables:
            if tables[0]["column"]["type"] == "INTEGER":
                db_query = f"SELECT * FROM {tables[0]['table_name']} WHERE {param}={param_value};"
            else:
                db_query = f'SELECT * FROM {tables[0]["table_name"]} WHERE {param}="{param_value}";'

        return db_query

    async def get_sqli_result(self, attack_value, attacker_db):
        """
        Executes the SQLi attack on the emulated database and returns the result.
        """
        db_query = self.map_query(attack_value)
        if db_query is None:
            # Return a SQL error message if the query could not be constructed
            if TannerConfig.get("SQLI", "type") == "MySQL":
                error_result = (
                    "You have an error in your SQL syntax; check the manual "
                    "that corresponds to your MySQL server version for the "
                    "right syntax to use near {} at line 1".format(attack_value["id"])
                )
            else:
                error_result = f"SQL ERROR: near {attack_value['id']}: syntax error"

            # Logging added to track SQLi execution errors
            self.logger.debug(f"Error while executing: {error_result}")
            result = dict(value=error_result, page=True)
        else:
            # Execute the emulated query on the attacker's database
            execute_result = await self.sqli_emulator.execute_query(db_query, attacker_db)
            if isinstance(execute_result, list):
                execute_result = " ".join([str(x) for x in execute_result])
            result = dict(value=execute_result, page=True)
        return result

    async def handle(self, attack_params, session):
        """
        Handles SQLi attacks by using the SQLi emulator to identify and respond to them.
        """
        if self.query_map is None:
            # Setup the database schema mapping if not already done
            self.query_map = await self.sqli_emulator.setup_db()
        # Create a database for the attacker's session
        attacker_db = await self.sqli_emulator.create_attacker_db(session)
        # Get the SQLi result based on the attack parameters and return the response
        result = await self.get_sqli_result(attack_params[0], attacker_db)
        return result
