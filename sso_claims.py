SUPPORTED_CLAIMS = ("name", "preferred_username", "email", "birthdate")
SUPPORTED_SCOPES = ("profile", "email")
SCOPE_CLAIMS = {
    "profile": ("name", "preferred_username", "birthdate"),
    "email": ("email",),
}


def normalize_scopes(scopes: object) -> list[str]:
    if scopes is None:
        return []
    if not isinstance(scopes, list):
        raise ValueError("scopes must be a list")

    unknown = sorted({str(scope) for scope in scopes} - set(SUPPORTED_SCOPES))
    if unknown:
        raise ValueError(f"Unsupported scopes: {', '.join(unknown)}")
    return [scope for scope in SUPPORTED_SCOPES if scope in scopes]


def claims_for_scopes(scopes: object) -> list[str]:
    included = {
        claim
        for scope in normalize_scopes(scopes)
        for claim in SCOPE_CLAIMS[scope]
    }
    return [claim for claim in SUPPORTED_CLAIMS if claim in included]
