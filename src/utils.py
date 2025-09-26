"""
Utility functions for Recon-ng MCP Server
"""

import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


def format_module_list(modules: List[Dict[str, Any]], format_type: str = "summary") -> Dict[str, Any]:
    """
    Format module list for AI consumption

    Args:
        modules: List of module dictionaries
        format_type: Type of formatting ("summary", "detailed", "categories")

    Returns:
        Formatted module data
    """
    try:
        if format_type == "categories":
            categories = {}
            for module in modules:
                category = module.get('category', 'unknown')
                if category not in categories:
                    categories[category] = []
                categories[category].append(module['name'])

            return {
                'format': 'categories',
                'categories': categories,
                'total_modules': len(modules),
                'total_categories': len(categories)
            }

        elif format_type == "detailed":
            return {
                'format': 'detailed',
                'modules': modules,
                'total_count': len(modules),
                'safe_modules': len([m for m in modules if m.get('safe_for_defensive', False)])
            }

        else:  # summary
            summary_modules = []
            for module in modules:
                summary_modules.append({
                    'name': module['name'],
                    'category': module.get('category', 'unknown'),
                    'safe': module.get('safe_for_defensive', False),
                    'description': module.get('description', '')[:100] + '...' if len(module.get('description', '')) > 100 else module.get('description', '')
                })

            return {
                'format': 'summary',
                'modules': summary_modules,
                'total_count': len(modules)
            }

    except Exception as e:
        logger.error(f"Error formatting module list: {e}")
        return {
            'format': 'error',
            'error': str(e),
            'modules': [],
            'total_count': 0
        }


def format_workspace_data(data: Dict[str, Any], include_empty: bool = False) -> Dict[str, Any]:
    """
    Format workspace data for AI consumption

    Args:
        data: Raw workspace data
        include_empty: Whether to include empty tables

    Returns:
        Formatted workspace data
    """
    try:
        formatted = {
            'workspace': data.get('workspace', 'unknown'),
            'timestamp': datetime.now().isoformat(),
            'tables': {},
            'summary': {}
        }

        tables_data = data.get('data', {})
        total_records = 0

        for table_name, records in tables_data.items():
            record_count = len(records) if records else 0
            total_records += record_count

            if record_count > 0 or include_empty:
                formatted['tables'][table_name] = {
                    'record_count': record_count,
                    'records': records if records else []
                }

        formatted['summary'] = {
            'total_tables': len(formatted['tables']),
            'total_records': total_records,
            'non_empty_tables': len([t for t in formatted['tables'].values() if t['record_count'] > 0])
        }

        return formatted

    except Exception as e:
        logger.error(f"Error formatting workspace data: {e}")
        return {
            'workspace': 'error',
            'error': str(e),
            'tables': {},
            'summary': {'total_tables': 0, 'total_records': 0}
        }


def sanitize_input(input_str: str, max_length: int = 1000) -> str:
    """
    Sanitize input string for security

    Args:
        input_str: Input string to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized string
    """
    try:
        if not isinstance(input_str, str):
            input_str = str(input_str)

        # Truncate if too long
        if len(input_str) > max_length:
            input_str = input_str[:max_length]

        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '&', '|', ';', '`', '$']
        for char in dangerous_chars:
            input_str = input_str.replace(char, '')

        # Remove control characters except newline and tab
        sanitized = ''.join(char for char in input_str if ord(char) >= 32 or char in '\n\t')

        return sanitized.strip()

    except Exception as e:
        logger.error(f"Error sanitizing input: {e}")
        return ""


def validate_json_data(data: Any) -> bool:
    """
    Validate that data can be safely serialized to JSON

    Args:
        data: Data to validate

    Returns:
        True if data is JSON-serializable
    """
    try:
        json.dumps(data)
        return True
    except (TypeError, ValueError) as e:
        logger.warning(f"Data not JSON serializable: {e}")
        return False


def create_error_response(error_message: str, error_code: str = "GENERAL_ERROR") -> Dict[str, Any]:
    """
    Create standardized error response

    Args:
        error_message: Error message
        error_code: Error code

    Returns:
        Standardized error response
    """
    return {
        'error': True,
        'error_code': error_code,
        'error_message': sanitize_input(error_message),
        'timestamp': datetime.now().isoformat()
    }


def create_success_response(data: Any, message: str = "Operation successful") -> Dict[str, Any]:
    """
    Create standardized success response

    Args:
        data: Response data
        message: Success message

    Returns:
        Standardized success response
    """
    try:
        return {
            'success': True,
            'message': message,
            'data': data,
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error creating success response: {e}")
        return create_error_response(f"Error creating response: {e}")


def parse_module_name(module_name: str) -> Dict[str, str]:
    """
    Parse module name into components

    Args:
        module_name: Full module name (e.g., 'recon/domains-hosts/bing_domain_web')

    Returns:
        Dictionary with module components
    """
    try:
        parts = module_name.split('/')
        if len(parts) >= 3:
            return {
                'category': parts[0],
                'subcategory': parts[1],
                'module': parts[2],
                'full_name': module_name
            }
        elif len(parts) == 2:
            return {
                'category': parts[0],
                'subcategory': '',
                'module': parts[1],
                'full_name': module_name
            }
        else:
            return {
                'category': 'unknown',
                'subcategory': '',
                'module': module_name,
                'full_name': module_name
            }
    except Exception as e:
        logger.error(f"Error parsing module name {module_name}: {e}")
        return {
            'category': 'error',
            'subcategory': '',
            'module': module_name,
            'full_name': module_name
        }


def get_module_categories(modules: List[Dict[str, Any]]) -> List[str]:
    """
    Extract unique categories from module list

    Args:
        modules: List of module dictionaries

    Returns:
        List of unique categories
    """
    try:
        categories = set()
        for module in modules:
            category = module.get('category', 'unknown')
            categories.add(category)
        return sorted(list(categories))
    except Exception as e:
        logger.error(f"Error extracting categories: {e}")
        return []


def format_execution_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format module execution result for display

    Args:
        result: Raw execution result

    Returns:
        Formatted result
    """
    try:
        formatted = {
            'execution_status': result.get('status', 'unknown'),
            'module': result.get('module', 'unknown'),
            'timestamp': datetime.now().isoformat()
        }

        if 'error' in result:
            formatted['error'] = result['error']
            formatted['success'] = False
        else:
            formatted['success'] = True
            formatted['message'] = result.get('message', 'Execution completed')

        if 'module_info' in result:
            formatted['module_info'] = result['module_info']

        if 'options_used' in result:
            formatted['options_used'] = result['options_used']

        return formatted

    except Exception as e:
        logger.error(f"Error formatting execution result: {e}")
        return create_error_response(f"Error formatting result: {e}")