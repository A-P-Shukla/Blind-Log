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
    - Fast Path: If key in sensitive_keys, masks the entire value using mask_value_fn.
    - Slow Path: If string value, scans using regex via mask_text_fn.
    """
    if visited is None:
        visited = set()

    # Base cases for recursion
    if data is None or isinstance(data, (int, float, bool)) and not force_mask:
        return data

    if data is None:
        return data

    # Cycle detection
    # Note: id() is used because dictionaries/lists are unhashable
    obj_id = id(data)
    if obj_id in visited:
        return "<CircularReference>"
        
    visited.add(obj_id)

    if isinstance(data, dict):
        masked_dict = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            
            # Fast Path: Key matches or we are forcibly masking inside a parent sensitive key
            if force_mask or any(sensitive in k_lower for sensitive in sensitive_keys):
                if isinstance(v, str):
                    masked_dict[k] = mask_value_fn(v)
                elif isinstance(v, (int, float)):
                    masked_dict[k] = mask_value_fn(str(v))
                else:
                    # It's a nested object under a sensitive key; traverse it enforcing masking on all scalar leaves
                    masked_dict[k] = walk_and_mask(v, sensitive_keys, mask_value_fn, mask_text_fn, visited, force_mask=True)
            else:
                # Recurse normally
                masked_dict[k] = walk_and_mask(v, sensitive_keys, mask_value_fn, mask_text_fn, visited, force_mask=False)
                
        visited.remove(obj_id)
        return masked_dict

    elif isinstance(data, list):
        masked_list = [walk_and_mask(item, sensitive_keys, mask_value_fn, mask_text_fn, visited, force_mask=force_mask) for item in data]
        visited.remove(obj_id)
        return masked_list
        
    elif isinstance(data, str):
        if force_mask:
            result = mask_value_fn(data)
        else:
            # Slow Path: Escaped or embedded PII inside a generic text block
            result = mask_text_fn(data)
        visited.remove(obj_id)
        return result

    # Fallback for primitive types forced to be masked
    if force_mask and isinstance(data, (int, float, bool)):
        result = mask_value_fn(str(data))
        visited.remove(obj_id)
        return result

    visited.remove(obj_id)
    return data
