"""Registration prototype for the Hermetic Harbor environment backend (TR-HB-1).

Harbor uses a closed `EnvironmentType` enum and an internal `_ENVIRONMENT_REGISTRY`
in `harbor.environments.factory`. This module provides the validated registration
path to dynamically register `hermetic` without modifying Harbor's upstream source.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from .errors import HarborDependencyError, HarborRegistrationError

PINNED_HARBOR_VERSION = "0.25.0"
HARBOR_RELEASE_DATE = "2026-10-25"
ENV_NAME = "hermetic"
MODULE_PATH = "hermetic_harbor.environment"
CLASS_NAME = "HermeticEnvironment"

logger = logging.getLogger(__name__)


def is_harbor_available() -> bool:
    """Return True if the approved harbor framework dependency is installed."""
    try:
        import harbor  # type: ignore[import-untyped]
        return getattr(harbor, "__version__", None) == PINNED_HARBOR_VERSION
    except ImportError:
        return False


def verify_harbor_dependency() -> Any:
    """Import and return the top-level harbor module or raise typed error."""
    try:
        import harbor  # type: ignore[import-untyped]
    except ImportError:
        raise HarborDependencyError(
            f"Required dependency 'harbor=={PINNED_HARBOR_VERSION}' is not installed"
        ) from None

    actual_version = getattr(harbor, "__version__", None)
    if actual_version != PINNED_HARBOR_VERSION:
        raise HarborDependencyError(
            f"Unsupported harbor version: expected '{PINNED_HARBOR_VERSION}', found '{actual_version}'"
        )
    return harbor


def register_into_targets(
    environment_type_cls: Any,
    registry: dict[Any, Any],
    env_name: str = ENV_NAME,
    module_path: str = MODULE_PATH,
    class_name: str = CLASS_NAME,
) -> Any:
    """Register the Hermetic backend into explicit EnvironmentType and registry objects.

    This function operates on target objects directly, allowing isolated testing
    with simulated Harbor modules as well as production registration.
    """
    if not isinstance(env_name, str) or not env_name.isidentifier():
        raise HarborRegistrationError("Environment name must be a valid identifier")
    if not isinstance(module_path, str) or not module_path:
        raise HarborRegistrationError("Module path must be non-empty")
    if not isinstance(class_name, str) or not class_name.isidentifier():
        raise HarborRegistrationError("Class name must be a valid identifier")

    member_name = env_name.upper()

    # Check if member already exists
    existing_member = getattr(environment_type_cls, member_name, None)
    if existing_member is not None and getattr(existing_member, "value", None) == env_name:
        member = existing_member
    else:
        # Dynamically inject member into the Enum using type.__setattr__
        # to bypass EnumMeta's prohibition against modifying member_map
        try:
            member = str.__new__(environment_type_cls, env_name)
            member._name_ = member_name
            member._value_ = env_name

            # Update Enum internal maps
            if hasattr(environment_type_cls, "_member_map_"):
                environment_type_cls._member_map_[member_name] = member
            if hasattr(environment_type_cls, "_value2member_map_"):
                environment_type_cls._value2member_map_[env_name] = member
            if hasattr(environment_type_cls, "_member_names_"):
                if member_name not in environment_type_cls._member_names_:
                    environment_type_cls._member_names_.append(member_name)

            type.__setattr__(environment_type_cls, member_name, member)
        except Exception as exc:
            raise HarborRegistrationError("Failed to extend EnvironmentType enum") from exc

    # Look up _EnvEntry class if available in factory, otherwise use namedtuple/tuple
    entry: Any
    factory_mod = sys.modules.get("harbor.environments.factory")
    env_entry_cls = getattr(factory_mod, "_EnvEntry", None)
    if env_entry_cls is not None:
        try:
            entry = env_entry_cls(module_path, class_name, None)
        except Exception:
            entry = (module_path, class_name, None)
    else:
        entry = (module_path, class_name, None)

    # Register under both enum member and string value
    registry[member] = entry
    registry[env_name] = entry

    return member


def unregister_from_targets(
    environment_type_cls: Any,
    registry: dict[Any, Any],
    env_name: str = ENV_NAME,
) -> bool:
    """Remove the Hermetic backend from target EnvironmentType and registry objects."""
    member_name = env_name.upper()
    removed = False

    member = getattr(environment_type_cls, member_name, None)
    if member is not None:
        registry.pop(member, None)
        if hasattr(environment_type_cls, "_member_map_"):
            environment_type_cls._member_map_.pop(member_name, None)
        if hasattr(environment_type_cls, "_value2member_map_"):
            environment_type_cls._value2member_map_.pop(env_name, None)
        if hasattr(environment_type_cls, "_member_names_"):
            if member_name in environment_type_cls._member_names_:
                environment_type_cls._member_names_.remove(member_name)
        if hasattr(environment_type_cls, member_name):
            try:
                type.__delattr__(environment_type_cls, member_name)
            except AttributeError:
                pass
        removed = True

    registry.pop(env_name, None)
    return removed


def register_hermetic(
    env_name: str = ENV_NAME,
    raise_if_missing: bool = True,
) -> bool:
    """Prototype registration of the sealed Hermetic backend into Harbor.

    Returns True if registration succeeded. If Harbor is not installed:
    - raises HarborDependencyError if raise_if_missing is True
    - returns False if raise_if_missing is False
    """
    try:
        verify_harbor_dependency()
    except HarborDependencyError:
        if raise_if_missing:
            raise
        return False

    try:
        from harbor.models.environment_type import EnvironmentType  # type: ignore[import-untyped]
        import harbor.environments.factory as factory  # type: ignore[import-untyped]
    except ImportError as exc:
        raise HarborRegistrationError("Failed to import Harbor environment internals") from exc

    registry = getattr(factory, "_ENVIRONMENT_REGISTRY", None)
    if not isinstance(registry, dict):
        raise HarborRegistrationError("Harbor _ENVIRONMENT_REGISTRY dictionary missing")

    register_into_targets(
        EnvironmentType,
        registry,
        env_name=env_name,
        module_path=MODULE_PATH,
        class_name=CLASS_NAME,
    )
    return True


def unregister_hermetic(env_name: str = ENV_NAME) -> bool:
    """Unregister the Hermetic backend from Harbor (primarily for test cleanup)."""
    try:
        from harbor.models.environment_type import EnvironmentType  # type: ignore[import-untyped]
        import harbor.environments.factory as factory  # type: ignore[import-untyped]
    except ImportError:
        return False

    registry = getattr(factory, "_ENVIRONMENT_REGISTRY", None)
    if not isinstance(registry, dict):
        return False

    return unregister_from_targets(EnvironmentType, registry, env_name=env_name)
