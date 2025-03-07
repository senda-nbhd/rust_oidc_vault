
/// Handler for the login route
pub async fn login_handler(
    session: Session,
    provider: Arc<KeycloakOidcProvider>,
) -> impl IntoResponse {
    // Start the authentication flow
    match provider.start_auth(&session, None).await {
        Ok(auth_uri) => Redirect::to(auth_uri.to_string().as_str()).into_response(),
        Err(e) => {
            tracing::error!("Failed to start authentication: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Handler for the login callback
pub async fn login_callback_handler(
    session: Session,
    provider: Arc<KeycloakOidcProvider>,
    code: String,
    state: String,
) -> impl IntoResponse {
    // Exchange the code for tokens
    match provider.handle_callback(&code, &state, &session, None).await {
        Ok(_) => {
            // Check if there's a redirect URL in the session
            match session.get::<String>("login_redirect").await {
                Ok(Some(redirect)) => {
                    // Remove the redirect from the session
                    let _ = session.remove::<String>("login_redirect").await;
                    Redirect::to(&redirect).into_response()
                }
                _ => {
                    // Default redirect to home
                    Redirect::to("/").into_response()
                }
            }
        }
        Err(e) => {
            tracing::error!("Authentication callback failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Handler for the logout route
pub async fn logout_handler(
    session: Session,
    provider: Arc<KeycloakOidcProvider>,
) -> impl IntoResponse {
    match provider.logout(&session).await {
        Ok(logout_uri) => Redirect::to(logout_uri.to_string().as_str()).into_response(),
        Err(e) => {
            tracing::error!("Logout failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
