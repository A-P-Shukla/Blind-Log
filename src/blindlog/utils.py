from typing import Any, Dict, List, Set, Callable
import copy

def walk_and_mask(
    data: Any, 
    sensitive_keys: Set[str], 
    mask_value_fn: Callable[[str], str],
    mask_text_fn: Callable[[str], str],
    visited: set = None
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
    if data is None or isinstance(data, (int, float, bool)):
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
            
            # Fast Path: Key matches
            if any(sensitive in k_lower for sensitive in sensitive_keys):
                if isinstance(v, str):
                    masked_dict[k] = mask_value_fn(v)
                elif isinstance(v, (int, float)):
                    masked_dict[k] = mask_value_fn(str(v))
                else:
                    # If it's a nested object under a sensitive key, we might want to mask the whole tree
                    # For simplicity in v1, we serialize to string and mask
                    masked_dict[k] = mask_value_fn(str(v))
            else:
                # Recurse
                masked_dict[k] = walk_and_mask(v, sensitive_keys, mask_value_fn, mask_text_fn, visited)
                
        visited.remove(obj_id)
        return masked_dict

    elif isinstance(data, list):
        masked_list = [walk_and_mask(item, sensitive_keys, mask_value_fn, mask_text_fn, visited) for item in data]
        visited.remove(obj_id)
        return masked_list
        
    elif isinstance(data, str):
        # Slow Path: Escaped or embedded PII inside a generic text block
        result = mask_text_fn(data)
        visited.remove(obj_id)
        return result

    visited.remove(obj_id)
    return data
