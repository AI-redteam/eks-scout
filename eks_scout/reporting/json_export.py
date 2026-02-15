"""JSON export for findings."""
import json
import logging


def export_findings_to_json(findings, filename="eks_findings.json", combos=None):
    """Export findings and combo analysis to a JSON file.

    Args:
        findings: List of finding dicts.
        filename: Output JSON file path.
        combos: Optional list of combo result dicts.
    """
    if not findings and not combos:
        logging.info("No findings to export.")
        return

    logging.info(f"Exporting {len(findings)} findings to {filename} in JSON format...")

    # Prepare combo results for serialization (sets aren't JSON-serializable)
    serializable_combos = None
    if combos:
        serializable_combos = []
        for combo in combos:
            c = dict(combo)
            if 'matched_finding_types' in c:
                c['matched_finding_types'] = sorted(c['matched_finding_types'])
            serializable_combos.append(c)

    output = {
        'findings': findings,
        'summary': {
            'total_findings': len(findings),
            'high_risk_combinations': len(combos) if combos else 0,
        },
    }
    if serializable_combos:
        output['high_risk_combinations'] = serializable_combos

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)
        logging.info(f"Successfully exported findings to {filename}")
    except IOError as e:
        logging.error(f"Failed to write JSON file {filename}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during JSON export: {e}")
