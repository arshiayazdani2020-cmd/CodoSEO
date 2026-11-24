//! Magic links: a 32-byte random token, stored hashed, valid for 15 minutes, usable once.
//!
//! The emailed link opens a small confirm page that POSTs the token back. Mail scanners that
//! prefetch every link in an email only issue a GET, so they can't burn the single-use token
//! before the person clicks it.

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, header};
use axum::response::{AppendHeaders, IntoResponse, Redirect, Response};
use codoseo_store::accounts::{SignIn, SignInOutcome};
use codoseo_store::auth::TokenPurpose;
use codoseo_store::quick::{self, UnlockCaps, UnlockSlot};
use serde::Deserialize;
use uuid::Uuid;

use super::{CurrentUser, email, safe_next, session, signup_policy};
use crate::abuse::{self, ClientIp};
use crate::assets;
use crate::auth::mailer::Email;
use crate::error::AppError;
use crate::render::{Hx, html};
use crate::state::AppState;

pub const MAGIC_TTL: time::Duration = time::Duration::minutes(15);

/// What the login card shows.
pub struct Card {
    pub email: String,
    pub next: String,
    pub error: Option<String>,
    /// The link was sent: show "check your email" instead of the form.
    pub sent: bool,
    pub github: bool,
    pub dev_hint: bool,
    /// On the cloud: signing in accepts the Terms and Privacy Policy, so the card links them.
    pub legal: bool,
}

#[derive(Template)]
#[template(path = "auth/login.html")]
pub struct LoginPage {
    pub card: Card,
}

#[derive(Template)]
#[template(path = "auth/card_partial.html")]
pub struct CardPartial {
    pub card: Card,
}

#[derive(Deserialize)]
pub struct LoginQuery {
    next: Option<String>,
}

pub async fn login_page(
    State(state): State<AppState>,
    user: Option<CurrentUser>,
    Query(q): Query<LoginQuery>,
) -> Result<Response, AppError> {
    let next = safe_next(q.next.as_deref()).to_owned();
    if user.is_some() {
        return Ok(Redirect::to(&next).into_response());
    }
    Ok(html(&LoginPage {
        card: card(&state, String::new(), next, None, false),
    })?
    .into_response())
}

fn card(state: &AppState, email: String, next: String, error: Option<String>, sent: bool) -> Card {
    Card {
        email,
        next,
        error,
        sent,
        github: state.config.github.is_some(),
        dev_hint: state.config.mode == crate::config::Mode::SelfHost,
        legal: state.config.mode == crate::config::Mode::Cloud,
    }
}

#[derive(Deserialize)]
pub struct LoginForm {
    email: String,
    next: Option<String>,
}

pub async fn request_link(
    State(state): State<AppState>,
    hx: Hx,
    ClientIp(ip): ClientIp,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let next = safe_next(form.next.as_deref()).to_owned();
    let respond = |c: Card| -> Result<Response, AppError> {
        Ok(if hx.request {
            html(&CardPartial { card: c })?.into_response()
        } else {
            html(&LoginPage { card: c })?.into_response()
        })
    };

    let Some(address) = email::parse(&form.email) else {
        let err = Some("That doesn't look like an email address.".to_owned());
        return respond(card(&state, form.email.trim().to_owned(), next, err, false));
    };

    let today = time::OffsetDateTime::now_utc().date();
    let mut ip_hashes = Vec::new();
    if let Some(ip) = ip {
        let hash_for = |day: time::Date| {
            abuse::ip_hash(&state.config.secret_key, ip, day)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        ip_hashes.push(hash_for(today));
        if let Some(yesterday) = today.previous_day() {
            ip_hashes.push(hash_for(yesterday));
        }
    }
    let _ = issue_link(&state, address, &next, None, Some(&ip_hashes)).await?;

    respond(card(&state, address.to_owned(), next, None, true))
}

/// A no-signup audit a sign-in link should attach to the new account when it is used.
pub struct AuditLink<'a> {
    pub crawl_id: Uuid,
    pub domain: &'a str,
}

/// What [`issue_link`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOutcome {
    Sent,
    /// An audit's unlock form already sent its share of emails this hour (nothing was sent).
    Throttled(UnlockSlot),
    LoginThrottled,
}

/// Stores a magic-link token for `address` and emails the link. With an `audit`, the link also
/// carries the audit's crawl id, and using it attaches the audited site to the account. Those
/// links are capped per audit and per recipient (see [`quick::create_unlock_token`]).
pub async fn issue_link(
    state: &AppState,
    address: &str,
    next: &str,
    audit: Option<AuditLink<'_>>,
    login_ip_hashes: Option<&[String]>,
) -> Result<LinkOutcome, AppError> {
    let token = session::random_token();
    let token_hash = session::hash(&token);
    let mut payload = serde_json::json!({ "email": address, "next": next });
    match &audit {
        None => {
            let canonical = email::canonical(address);
            let allowed = codoseo_store::auth::create_login_link_token(
                &state.pool,
                &canonical,
                login_ip_hashes.unwrap_or(&[]),
                &token_hash,
                payload,
                MAGIC_TTL,
                codoseo_store::auth::LoginLinkCaps::DEFAULT,
            )
            .await?;
            if !allowed {
                return Ok(LinkOutcome::LoginThrottled);
            }
        }
        Some(a) => {
            let canonical = email::canonical(address);
            payload["audit"] = serde_json::json!(a.crawl_id);
            payload["canonical"] = serde_json::json!(canonical);
            let slot = quick::create_unlock_token(
                &state.pool,
                a.crawl_id,
                &canonical,
                &token_hash,
                payload,
                MAGIC_TTL,
                UnlockCaps::DEFAULT,
            )
            .await?;
            if slot != UnlockSlot::Created {
                return Ok(LinkOutcome::Throttled(slot));
            }
        }
    }

    let mut link = state.config.base_url.clone();
    link.set_path(&format!("/auth/magic/{token}"));
    let (subject, text) = match audit {
        None => (
            "Your CodoSEO sign-in link".to_owned(),
            format!(
                "Sign in to CodoSEO:\n\n{link}\n\nThe link works once and expires in 15 minutes. \
                 If you didn't ask for it, you can ignore this email."
            ),
        ),
        Some(a) => (
            format!("Your CodoSEO report for {}", a.domain),
            format!(
                "Open the full CodoSEO report for {}:\n\n{link}\n\nThe link works once and \
                 expires in 15 minutes. It also starts weekly monitoring of the site, with an \
                 email when something important breaks. If you didn't ask for it, you can \
                 ignore this email.",
                a.domain
            ),
        ),
    };
    if let Err(e) = state
        .mailer
        .send(Email {
            to: address.to_owned(),
            subject,
            text,
            html: None,
        })
        .await
    {
        // The page says "if the address is registered we sent a link" either way; a broken mail
        // server is for the operator to see in the logs, not for the visitor to probe.
        tracing::error!(error = %e, "could not send the sign-in link");
    }
    Ok(LinkOutcome::Sent)
}

#[derive(Template)]
#[template(path = "auth/confirm.html")]
pub struct ConfirmPage {
    pub token: String,
}

pub async fn confirm_page(Path(token): Path<String>) -> Result<Response, AppError> {
    Ok(html(&ConfirmPage { token })?.into_response())
}

pub async fn consume(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let token_hash = session::hash(&token);
    let used =
        codoseo_store::auth::consume_token(&state.pool, TokenPurpose::MagicLink, &token_hash)
            .await?
            .ok_or_else(|| {
                AppError::BadRequest(
                    "This sign-in link has expired or was already used. Ask for a new one."
                        .to_owned(),
                )
            })?;

    let payload = used.payload.unwrap_or_default();
    let result = complete_magic_sign_in(&state, payload, &headers).await;
    // Only transient/internal processing failures are retryable. Permanent policy or request
    // errors (for example, signups being closed) must leave the token consumed.
    let should_restore = matches!(&result, Err(AppError::Unavailable | AppError::Internal(_)));
    if should_restore {
        match codoseo_store::auth::unconsume_token(
            &state.pool,
            TokenPurpose::MagicLink,
            &token_hash,
        )
        .await
        {
            Ok(true) => tracing::warn!(
                "magic-link processing failed; the unexpired token was restored for retry"
            ),
            Ok(false) => {
                tracing::error!("magic-link processing failed and its token could not be restored")
            }
            Err(error) => {
                tracing::error!(%error, "magic-link processing failed and token recovery also failed")
            }
        }
    }
    result
}

/// Completes the side effects before creating the browser session. If any step fails, the
/// caller restores the still-unexpired magic-link token so the visitor can retry.
async fn complete_magic_sign_in(
    state: &AppState,
    payload: serde_json::Value,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    let address = payload["email"]
        .as_str()
        .ok_or_else(|| AppError::internal("magic link without an email"))?;
    let next = safe_next(payload["next"].as_str()).to_owned();
    let canonical = email::canonical(address);
    let outcome = codoseo_store::accounts::sign_in(
        &state.pool,
        &SignIn {
            email: address,
            canonical: &canonical,
            github_id: None,
        },
        signup_policy(state),
    )
    .await?;
    let account = match outcome {
        SignInOutcome::Existing(a) | SignInOutcome::Created(a) => a,
        SignInOutcome::SignupsClosed => return Err(signups_closed()),
    };

    // Complete database work before issuing a session cookie. A failure must not leave a
    // session row that the browser never received.
    codoseo_store::accounts::record_email_click(&state.pool, account.id).await?;

    // Create the session before the Quick Audit's final event write. If attachment fails,
    // revoke this not-yet-delivered session before restoring the magic link for retry.
    let cookie = session::start(state, account.id).await?;

    // A link from the no-signup audit also attaches the audited site to the account.
    let audit = payload["audit"]
        .as_str()
        .and_then(|a| Uuid::parse_str(a).ok());
    let destination = if let Some(audit) = audit {
        match crate::routes::quick::attach_after_login(state, &account, audit, headers).await {
            Ok(destination) => destination,
            Err(error) => {
                if let Err(revoke_error) = session::revoke_cookie(state, &cookie).await {
                    tracing::error!(%revoke_error, "could not revoke a session after Quick Audit attachment failed");
                }
                return Err(error);
            }
        }
    } else {
        next
    };

    if audit.is_some() {
        let spent = crate::routes::quick::clear_claim_cookie(state);
        Ok((
            AppendHeaders([(header::SET_COOKIE, cookie), (header::SET_COOKIE, spent)]),
            Redirect::to(&destination),
        )
            .into_response())
    } else {
        Ok(([(header::SET_COOKIE, cookie)], Redirect::to(&destination)).into_response())
    }
}

pub fn signups_closed() -> AppError {
    AppError::Forbidden(
        "Signups are closed on this CodoSEO instance. Ask its owner to let you in.".to_owned(),
    )
}

/// Template helper so auth pages can reference assets without the app shell.
pub fn asset(name: &str) -> &'static str {
    assets::url(name)
}
