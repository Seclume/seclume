"""Fail CI if any required framework case is absent, skipped or failed."""
import sys
from pathlib import Path
from require_pool_tests import read_report

EXPECTED = {
    "Jooq": ("jooqInsertsQueriesBatchesAndRollsBack", "earlyCursorCloseLeavesTheConnectionUsable",
             "databaseErrorRollsBackEarlierWrites"),
    "MyBatis": ("myBatisGeneratedKeysDynamicSqlBatchAndNull", "failedBatchRollsBackEarlierWrites",
                "earlyCursorCloseAllowsAnotherQuery"),
    "Liquibase": ("liquibaseUpdatesRollsBackAndUpdatesAgain", "repeatedDeploymentDoesNotRepeatChanges",
                  "failedDataMigrationRollsBackAndReleasesLock"),
}


def require(database, reports):
    if database not in ("Postgres", "MySql", "SqlServer", "Oracle"):
        raise ValueError("unknown database")
    for framework, methods in EXPECTED.items():
        suite = f"{framework}On{database}Test"
        report = reports / f"TEST-space.seclume.frameworks.{suite}.xml"
        cases = {case.get("name"): case for case in read_report(report).iter("testcase")}
        for method in methods:
            case = cases.get(method)
            if case is None or any(case.find(tag) is not None for tag in ("skipped", "failure", "error")):
                raise ValueError(f"required test did not pass: {suite}.{method}")
    return sum(map(len, EXPECTED.values()))


if __name__ == "__main__":
    print(f"{require(sys.argv[1], Path('seclume-spring-test/target/surefire-reports'))} framework tests passed")
