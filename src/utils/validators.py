import json
from typing import Tuple, Optional


def validate_analysis_input(input_line: str) -> Tuple[bool, Optional[str]]:
    """Validate input line from batch processing.

    Args:
        input_line: JSON string containing analysis data

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        data = json.loads(input_line.strip())
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {str(e)}"

    if not isinstance(data, list):
        return False, "Input must be a list"

    if len(data) < 2:
        return False, "Input must contain at least [id, analysis_data]"

    analysis_id = data[0]
    if not analysis_id:
        return False, "Analysis ID cannot be empty"

    analysis_data = data[1]
    if not isinstance(analysis_data, list) or len(analysis_data) < 2:
        return False, "Analysis data must be [status, data]"

    return True, None


def validate_domain_name_safe(domain: str) -> bool:
    """
    Args:
        domain: Domain name to validate

    Returns:
        True if domain appears valid
    """
    if not isinstance(domain, str):
        return False

    if not domain:
        return False

    # Basic checks that won't break existing functionality
    if not domain.endswith('.'):
        return False

    if len(domain) > 255:  # RFC limit
        return False

    # Allow existing domains to pass through
    return True


def validate_zone_name(zone_name: str) -> bool:
    """Validate zone name format."""
    if not zone_name:
        return False

    return validate_domain_name_safe(zone_name)


def validate_error_codes(error_codes: list) -> bool:
    """Validate list of error codes."""
    if not isinstance(error_codes, list):
        return False

    # Allow empty lists (no errors found)
    return True