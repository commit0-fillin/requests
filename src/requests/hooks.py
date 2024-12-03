"""
requests.hooks
~~~~~~~~~~~~~~

This module provides the capabilities for the Requests hooks system.

Available hooks:

``response``:
    The response generated from a Request.
"""
HOOKS = ['response']

def dispatch_hook(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    if key not in hooks:
        return hook_data
    
    if hasattr(hooks[key], '__call__'):
        hooks[key] = [hooks[key]]
    
    for hook in hooks[key]:
        _hook_data = hook(hook_data, **kwargs)
        if _hook_data is not None:
            hook_data = _hook_data
    
    return hook_data
