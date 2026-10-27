"""``HarnessEngine.impact`` — CVE impact analysis, bound to context."""

from __future__ import annotations

from pathlib import Path

from traust_contracts import DeploymentConfigMissing

from traust_engine import locations, storage
from traust_engine._ops_base import ContextOps


class ImpactOps(ContextOps):
    def _analysis_results_location(self) -> str | None:
        return locations.analysis_results_location(self._loc)

    def _portfolio_graph_location(self) -> str:
        return locations.require(locations.portfolio_graph_location(self._loc), "portfolio_graph")

    def _portfolio_graph_db(self) -> Path:
        return locations.require(
            locations.local_path(self._portfolio_graph_location()), "portfolio_graph"
        )

    def results_dir(self) -> Path | None:
        """Localized analysis-results root for SBOM/image tiers."""
        loc = self._analysis_results_location()
        if not loc:
            return None
        try:
            return storage.localize(loc)
        except storage.StorageError:
            return None

    def portfolio_graph_path(self) -> Path:
        """Localized portfolio graph DB for impact analysis."""
        raw = self._portfolio_graph_location()
        try:
            path = storage.localize(raw)
        except storage.StorageError as e:
            raise DeploymentConfigMissing(f"portfolio graph unusable: {e}") from e
        if path is None or not path.exists():
            raise DeploymentConfigMissing(f"portfolio graph not found at {raw}")
        return path

    def analyze(
        self,
        *,
        cve: str,
        module: str,
        ecosystem: str = "go",
        osv_url: str | None = None,
        advisory_file: str | None = None,
        verified_versions: tuple[str, ...] = (),
        verified_by: str | None = None,
        symbols: str = "",
        packages: str = "",
        feature_desc: str | None = None,
        out: str | None = None,
        jobs: int = 4,
        skip_scan: bool = False,
        db: str | None = None,
    ) -> int:
        """Analyze one advisory across the portfolio graph.

        The range and fixed version come from the advisory's OSV record, fetched
        from ``osv_url`` (the deployment's feeds) or read from ``advisory_file``
        when the API is unreachable; a caller never supplies them. The one exception is
        ``verified_versions``: versions below-range review verified affected, each backed
        by an `applicable` verdict in ``verified_by``."""
        import sys

        from traust_engine.impact.advisory import AdvisoryUnavailable, resolve, with_verified
        from traust_engine.impact.analyzer import ImpactParams, _execute, valid_advisory_id

        if not valid_advisory_id(cve):
            print(f"ERROR: '{cve}' is not a valid advisory ID", file=sys.stderr)
            return 2
        try:
            if bool(verified_versions) != bool(verified_by):
                raise AdvisoryUnavailable("verified versions and their verdicts file go together")
            advisory = resolve(cve, module, ecosystem, osv_url=osv_url, advisory_file=advisory_file)
            if verified_versions:
                advisory = with_verified(advisory, verified_versions, verified_by)
        except AdvisoryUnavailable as e:
            print(f"ERROR: {cve} not assessed: {e}", file=sys.stderr)
            return 2
        print(f"Advisory {', '.join(advisory.sources)}: {module} {advisory.vulnerable_range}")

        params = ImpactParams(
            cve=cve,
            module=module,
            ecosystem=ecosystem,
            advisory=advisory,
            symbols=symbols,
            packages=packages,
            feature_desc=feature_desc,
            out=out,
            jobs=jobs,
            skip_scan=skip_scan,
        )

        raw_db = db or self._portfolio_graph_location()
        try:
            db_path = storage.localize(raw_db)
        except storage.StorageError as e:
            import sys

            print(f"ERROR: portfolio graph unusable: {e}", file=sys.stderr)
            return 2
        if db_path is None or not db_path.exists():
            import sys

            print(f"ERROR: portfolio graph not found at {raw_db}", file=sys.stderr)
            return 1

        return _execute(params, db_path, self._analysis_results_location())
