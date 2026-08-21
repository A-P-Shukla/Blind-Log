from typing import Any, Set, Callable
from blindlog.rules import normalize_key

def walk_and_mask(
    data: Any, 
    sensitive_keys: Set[str], 
    mask_value_fn: Callable[[str], str],
    mask_text_fn: Callable[[str], str],
    visited: set = None,
    force_mask: bool = False
) -> Any:
    """
    Recursively walks through dictionaries, lists, tuples, and sets to mask sensitive data.
    Implements DFS with cycle detection to prevent infinite recursion on self-referencing objects.
    
    Hybrid Strategy:
    - Fast Path: If key matches (exact, suffix with _/-./ delimiters, or camelCase normalized), mask value.
    - Slow Path: If string value, scans using regex via mask_text_fn.
    """
    if visited is None:
        visited = set()

    # Fix #6: Use null byte sentinel for type-prefixed masking (cannot appear in JSON)
    if data is None:
        if force_mask:
            return mask_value_fn("\x00NoneType\x00")
        return data

    if isinstance(data, bool) and not force_mask:
        return data
    if isinstance(data, bool) and force_mask:
        return mask_value_fn(f"\x00bool\x00{data}")

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
            # Fix #3 + #4: Normalize camelCase to snake_case before matching
            k_normalized = normalize_key(str(k))
            
            # Exact match, suffix match (with _, -, . delimiters)
            is_sensitive = (
                force_mask
                or k_normalized in sensitive_keys
                or any(
                    k_normalized.endswith("_" + s) 
                    or k_normalized.endswith("-" + s) 
                    or k_normalized.endswith("." + s)
                    for s in sensitive_keys
                )
            )
            
            if is_sensitive:
                # bool is a subclass of int — check bool before int/float
                if isinstance(v, str):
                    masked_dict[k] = mask_value_fn(v)
                elif isinstance(v, bool):
                    masked_dict[k] = mask_value_fn(f"\x00bool\x00{v}")
                elif isinstance(v, (int, float)):
                    masked_dict[k] = mask_value_fn(str(v))
                elif v is None:
                    masked_dict[k] = mask_value_fn("\x00NoneType\x00")
                else:
                    masked_dict[k] = walk_and_mask(v, sensitive_keys, mask_value_fn, mask_text_fn, visited, force_mask=True)
            else:
                masked_dict[k] = walk_and_mask(v, sensitive_keys, mask_value_fn, mask_text_fn, visited, force_mask=False)
                
        visited.remove(obj_id)
        return masked_dict

    elif isinstance(data, list):
        masked_list = [
            walk_and_mask(item, sensitive_keys, mask_value_fn, mask_text_fn, visited, force_mask=force_mask)
            for item in data
        ]
        visited.remove(obj_id)
        return masked_list

    elif isinstance(data, tuple):
        # Tuples under sensitive keys previously leaked plaintext; walk like lists.
        masked_tuple = tuple(
            walk_and_mask(item, sensitive_keys, mask_value_fn, mask_text_fn, visited, force_mask=force_mask)
            for item in data
        )
        visited.remove(obj_id)
        return masked_tuple

    elif isinstance(data, (set, frozenset)):
        # Preserve container type when possible; fall back to list if items become unhashable.
        masked_items = [
            walk_and_mask(item, sensitive_keys, mask_value_fn, mask_text_fn, visited, force_mask=force_mask)
            for item in data
        ]
        visited.remove(obj_id)
        try:
            return type(data)(masked_items)
        except TypeError:
            return masked_items

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
