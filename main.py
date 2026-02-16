#!/usr/bin/env python3
"""EKS Scout - AWS EKS Passive Security Scanner.

Backward-compatible entry point. Use 'eks-scout scan' for the recommended CLI.

Usage:
    python main.py --cluster-name <name> --region <region> [options]
"""
import argparse
import logging
import sys
from datetime import datetime

from eks_scout.scanner import scan
from eks_scout.config import SEVERITY_RANK
from eks_scout.reporting.csv_export import export_findings_to_csv
from eks_scout.reporting.json_export import export_findings_to_json
from eks_scout.reporting.html_export import export_findings_to_html
from eks_scout.reporting.console import print_summary
from eks_scout.cli import BANNER


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    parser = argparse.ArgumentParser(description="AWS EKS Security Scanner (Read-Only)")
    parser.add_argument("--cluster-name", required=True, help="Name of the EKS cluster")
    parser.add_argument("--region", required=True, help="AWS region of the EKS cluster")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--context", help="kubectl context to use")
    parser.add_argument("-o", "--output-file", default="eks_findings_plextrac.csv",
                        help="Output CSV file name")
    parser.add_argument("-f", "--output-format", choices=['csv', 'json', 'html'], default=None,
                        help="Output format: csv, json, or html (default: csv + html)")
    parser.add_argument("--config", help="Path to configuration file (YAML or JSON)")
    parser.add_argument("--show-suppressed", action="store_true",
                        help="Include suppressed findings in output with 'Suppressed' status")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--fail-on", choices=['critical', 'high', 'medium', 'low'],
                        help="Exit with code 2 if any finding meets or exceeds this severity (for CI/CD gating)")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    print(BANNER)

    start_time = datetime.now()
    logging.info(f"Starting EKS Scout scan for cluster '{args.cluster_name}' in region '{args.region}'...")
    logging.info(f"Using AWS Profile: '{args.profile or 'default'}' | Using kubectl Context: '{args.context or 'default'}'")
    logging.info("NOTE: This tool uses read-only kubectl and aws cli commands.")

    result = scan(
        cluster_name=args.cluster_name,
        region=args.region,
        profile=args.profile,
        context=args.context,
        config_file=args.config,
        show_suppressed=args.show_suppressed,
    )

    if result is None:
        logging.error("Scan aborted due to dependency check failure.")
        sys.exit(1)

    end_time = datetime.now()
    duration = end_time - start_time
    logging.info(f"--- Scan Complete (duration: {duration}) ---")

    if not result.findings and not result.suppressed:
        logging.info("No specific security issues found based on the current checks.")
        return

    print_summary(result.findings, suppressed_count=result.suppressed_count,
                  combos=result.combos, duration=duration)

    output_file = args.output_file
    scan_metadata = {
        'cluster_name': args.cluster_name,
        'region': args.region,
        'profile': args.profile or '',
        'scan_time': end_time.strftime('%Y-%m-%d %H:%M:%S'),
    }

    if args.output_format is None:
        # Default: emit both CSV and HTML
        export_findings_to_csv(result.findings, output_file)
        html_file = output_file.rsplit('.', 1)[0] + '.html' if '.' in output_file else output_file + '.html'
        export_findings_to_html(result.findings, html_file,
                                combos=result.combos, scan_metadata=scan_metadata)
    elif args.output_format == 'csv':
        export_findings_to_csv(result.findings, output_file)
    elif args.output_format == 'json':
        export_findings_to_json(result.findings, output_file, combos=result.combos)
    elif args.output_format == 'html':
        if output_file == 'eks_findings_plextrac.csv':
            output_file = 'eks_scout_report.html'
        export_findings_to_html(result.findings, output_file,
                                combos=result.combos, scan_metadata=scan_metadata)

    # CI/CD exit code gating
    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on.capitalize()]
        for finding in result.findings:
            finding_rank = SEVERITY_RANK.get(finding.get('severity', ''), 99)
            if finding_rank <= threshold:
                logging.error(f"Failing: found finding with severity '{finding['severity']}' "
                              f"(threshold: {args.fail_on})")
                sys.exit(2)
        logging.info(f"No findings at or above '{args.fail_on}' severity. Exiting 0.")


if __name__ == "__main__":
    main()
