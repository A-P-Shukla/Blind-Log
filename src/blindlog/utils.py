from typing import Any, Dict, List, Set, Callable
import copy

def walk_and_mask(
    data: Any, 
    sensitive_keys: Set[str], 
    mask_value_fn: Callable[[str], str],
    mask_text_fn: Callable[[str], str],
    visited: set = None,
    force_mask: bool = False
) -> Any:
    """
    Recursively walks through dictionaries and lists to mask sensitive data.
    Implements DFS with cycle detection to prevent infinite recursion on self-referencing objects.
    
    Hybrid Strategy:
    - Fast Path: If key exactly matches or ends with a sensitive key suffix, mask value.
    - Slow Path: If string value, scans using regex via mask_text_fn.
    """
    if visited is None:
        visited = set()

    # Fix #2 + #12: Separate base cases with type-prefixed masking for None/bool
    if data is None:
        if force_mask:
            return mask_value_fn("__NoneType__:None")
        return data

    if isinstance(data, bool) and not force_mask:
        return data
    if isinstance(data, bool) and force_mask:
        return mask_value_fn(f"__bool__:{data}")

    if isinstance(data, (int, float)) and not force_mask:
        return data

    # Cycle detection
    obj_id = id(data)
    if obj_id in visited:
        return "<CircularReference>"
        
    visited.add(obj_id)

    if isinstance(data, dict):
        masked_dict = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            
            # Fix #1: Suffix matching — catches refresh_token, old_password, x_api_key
            # while still rejecting token_count, email_verified
            is_sensitive = (
                force_mask
                or k_lower in sensitive_keys
                or any(k_lower.endswith("_" + s) or k_lower.endswith("-" + s) for s in sensitive_keys)
            )
            
            if is_sensitive:
                if isinstance(v, str):
                    masked_dict[k] = mask_value_fn(v)
                elif isinstance(v, (int, float)):
                    masked_dict[k] = mask_value_fn(str(v))
                elif isinstance(v, bool):
                    masked_dict[k] = mask_value_fn(f"__bool__:{v}")
                elif v is None:
                    masked_dict[k] = mask_value_fn("__NoneType__:None")
                else:
                    masked_dict[k] = walk_and_mask(v, sensitive_keys, mask_value_fn, mask_text_fn, visited, force_mask=True)
            else:
                masked_dict[k] = walk_and_mask(v, sensitive_keys, mask_value_fn, mask_text_fn, visited, force_mask=False)
                
        visited.remove(obj_id)
        return masked_dict

    elif isinstance(data, list):
        masked_list = [walk_and_mask(item, sensitive_keys, mask_value_fn, mask_text_fn, visited, force_mask=force_mask) for item in data]
        visited.remove(obj_id)
        return masked_list

    # Fix #6: Handle bytes type
    elif isinstance(data, bytes):
        try:
            decoded = data.decode('utf-8', errors='ignore')
            result = mask_value_fn(decoded) if force_mask else mask_text_fn(decoded)
            visited.remove(obj_id)
            return result
        except Exception:
            visited.remove(obj_id)
            return data
        
    elif isinstance(data, str):
        if force_mask:
            result = mask_value_fn(data)
        else:
            result = mask_text_fn(data)
        visited.remove(obj_id)
        return result

    # Fallback for primitive types forced to be masked
    if force_mask and isinstance(data, (int, float)):
        result = mask_value_fn(str(data))
        visited.remove(obj_id)
        return result

    visited.remove(obj_id)
    return data
