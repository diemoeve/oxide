"""Authentication router."""

from fastapi import APIRouter, HTTPException, Request, Response, status

from ..auth import (
    SESSION_COOKIE_NAME,
    authenticate_user,
    create_user_session,
    invalidate_session,
)
from ..deps import CurrentUser
from ..schemas import LoginRequest, LoginResponse, UserInfo

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
async def login(request: Request, response: Response, body: LoginRequest):
    """
    Authenticate with username and password.

    Sets a session cookie on success.
    """
    user = await authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Get client info for session
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    token = await create_user_session(user["id"], ip_address, user_agent)

    # Set session cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=False,  # Set True in production with HTTPS
        samesite="lax",
        max_age=86400 * 7,
    )

    return LoginResponse(
        success=True,
        token=token,
        user={"id": user["id"], "username": user["username"]},
    )


@router.post("/logout")
async def logout(response: Response, current_user: CurrentUser):
    """
    Log out the current user.

    Clears the session cookie.
    """
    # Note: We don't have access to the token here directly
    # The cookie will be cleared, and the session will expire naturally
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"success": True}


@router.get("/me", response_model=UserInfo)
async def get_current_user_info(current_user: CurrentUser):
    """Get information about the currently authenticated user."""
    return UserInfo(id=current_user["id"], username=current_user["username"])
