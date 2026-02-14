"""CSV export for Plextrac-compatible findings."""
import csv
import logging


def export_findings_to_csv(findings, filename="eks_findings_plextrac.csv"):
    """Export findings to a CSV file formatted for Plextrac import.

    Args:
        findings: List of finding dicts.
        filename: Output CSV file path.
    """
    if not findings:
        logging.info("No findings to export.")
        return

    fieldnames = [
        "Finding Name",
        "Severity",
        "Status",
        "Description",
        "Recommendation",
        "Vulnerability References",
        "Affected Components",
        "Tags",
    ]

    logging.info(f"Exporting {len(findings)} findings to {filename}...")
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for finding in findings:
                affected_component = f"{finding['namespace']}/{finding['name']}"
                if finding['namespace'] == '(cluster)':
                    affected_component = finding['name']

                writer.writerow({
                    "Finding Name": finding['type'],
                    "Severity": finding['severity'],
                    "Status": "Open",
                    "Description": finding['details'],
                    "Recommendation": finding['recommendation'],
                    "Vulnerability References": finding['reference'],
                    "Affected Components": affected_component,
                    "Tags": f"EKS,Kubernetes,Security,{finding['asset_type']}",
                })
        logging.info(f"Successfully exported findings to {filename}")
    except IOError as e:
        logging.error(f"Failed to write CSV file {filename}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during CSV export: {e}")
