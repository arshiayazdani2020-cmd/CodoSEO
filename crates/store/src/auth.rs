//! Login tokens (magic links, start-monitoring confirmations) and sessions. Only hashes are
//! stored: the web crate hashes the random token or session ID before it reaches here.

use sqlx::{FromRow, PgExecutor, PgPool};
use time::Duration;
use uuid::Uuid;

use crate::accounts::{ACCOUNT_COLUMNS, Account};

/// Mirrors the `login_token_purpose` Postgres enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenPurpose {
    MagicLink,
    StartMonitoring,
    /// The "Keep monitoring?" email's link, for an inactive Free account.
    ResumeMonitoring,
}

impl TokenPurpose {
    fn slug(self) -> &'static str {
        match self {
            TokenPurpose::MagicLink => "magic_link",
            TokenPurpose::StartMonitoring => "start_monitoring",
            TokenPurpose::ResumeMonitoring => "resume_monitoring",
        }
    }
}

/// Stores a single-use token that expires after `ttl`.
pub async fn create_token(
    executor: impl PgExecutor<'_>,
    purpose: TokenPurpose,
    token_hash: &[u8],
    account_id: Option<Uuid>,
    payload: Option<serde_json::Value>,
    ttl: Duration,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO login_tokens (account_id, purpose, token_hash, payload, expires_at) \
         VALUES ($1, $2::login_token_purpose, $3, $4, now() + make_interval(secs => $5)) \
         RETURNING id",
    )
    .bind(account_id)
    .bind(purpose.slug())
    .bind(token_hash)
    .bind(payload)
    .bind(ttl.as_seconds_f64())
    .fetch_one(executor)
    .await
}

#[derive(Debug, Clone, FromRow)]
pub struct ConsumedToken {
    pub account_id: Option<Uuid>,
    pub payload: Option<serde_json::Value>,
}

/// Marks a token used and returns it, in one statement, so a token works exactly once even
/// when two requests race. Returns `None` for an unknown, used or expired token.
pub async fn consume_token(
    executor: impl PgExecutor<'_>,
    purpose: TokenPurpose,
    token_hash: &[u8],
) -> Result<Option<ConsumedToken>, sqlx::Error> {
    sqlx::query_as(
        "UPDATE login_tokens SET used_at = now() \
         WHERE token_hash = $1 AND purpose = $2::login_token_purpose \
           AND used_at IS NULL AND expires_at > now() \
         RETURNING account_id, payload",
    )
    .bind(token_hash)
    .bind(purpose.slug())
    .fetch_optional(executor)
    .await
}

/// Makes a token usable again after [`consume_token`] when what it was for failed half-way, so
/// the person's link still works. Only an unexpired token comes back.
pub async fn unconsume_token(
    executor: impl PgExecutor<'_>,
    purpose: TokenPurpose,
    token_hash: &[u8],
) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE login_tokens SET used_at = NULL \
         WHERE token_hash = $1 AND purpose = $2::login_token_purpose \
           AND used_at IS NOT NULL AND expires_at > now()",
    )
    .bind(token_hash)
    .bind(purpose.slug())
    .execute(executor)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Whether the token could still be consumed (known, unused, unexpired), without using it. For
/// links that must not change anything on a GET: mail scanners open every link.
pub async fn token_is_live(
    executor: impl PgExecutor<'_>,
    purpose: TokenPurpose,
    token_hash: &[u8],
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM login_tokens \
         WHERE token_hash = $1 AND purpose = $2::login_token_purpose \
           AND used_at IS NULL AND expires_at > now())",
    )
    .bind(token_hash)
    .bind(purpose.slug())
    .fetch_one(executor)
    .await
}

/// The payload of a token that could still be consumed, without using it: for the confirm page
/// of a link that must not change anything on a GET. `None` when the token is unknown, used or
/// expired; a live token without a payload gives `Some(Value::Null)`.
pub async fn live_token_payload(
    executor: impl PgExecutor<'_>,
    purpose: TokenPurpose,
    token_hash: &[u8],
) -> Result<Option<serde_json::Value>, sqlx::Error> {
    let row: Option<(Option<serde_json::Value>,)> = sqlx::query_as(
        "SELECT payload FROM login_tokens \
         WHERE token_hash = $1 AND purpose = $2::login_token_purpose \
           AND used_at IS NULL AND expires_at > now()",
    )
    .bind(token_hash)
    .bind(purpose.slug())
    .fetch_optional(executor)
    .await?;
    Ok(row.map(|(payload,)| payload.unwrap_or(serde_json::Value::Null)))
}

/// Caps for ordinary sign-in email requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginLinkCaps {
    pub per_address_per_hour: i64,
    pub per_ip_per_hour: i64,
}
impl LoginLinkCaps {
    pub const DEFAULT: LoginLinkCaps = LoginLinkCaps {
        per_address_per_hour: 3,
        per_ip_per_hour: 10,
    };
}

/// Atomically checks ordinary-login email limits and stores the token. IP hashes are daily
/// salted; callers pass today's and yesterday's hashes so a rolling hour survives UTC midnight.
pub async fn create_login_link_token(
    pool: &PgPool,
    canonical: &str,
    ip_hashes: &[String],
    token_hash: &[u8],
    mut payload: serde_json::Value,
    ttl: Duration,
    caps: LoginLinkCaps,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('codoseo.login.email:' || $1))")
        .bind(canonical)
        .execute(&mut *tx)
        .await?;
    let mut lock_keys = ip_hashes.to_vec();
    lock_keys.sort();
    lock_keys.dedup();
    for key in &lock_keys {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('codoseo.login.ip:' || $1))")
            .bind(key)
            .execute(&mut *tx)
            .await?;
    }
    let (address_count, ip_count): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE payload->>'login_canonical' = $1), \
                count(*) FILTER (WHERE payload->>'login_ip_hash' = ANY($2)) \
         FROM login_tokens WHERE purpose = 'magic_link' \
           AND payload->>'login_source' = 'login' \
           AND created_at > now() - interval '1 hour'",
    )
    .bind(canonical)
    .bind(ip_hashes)
    .fetch_one(&mut *tx)
    .await?;
    if address_count >= caps.per_address_per_hour
        || (!ip_hashes.is_empty() && ip_count >= caps.per_ip_per_hour)
    {
        tx.commit().await?;
        return Ok(false);
    }
    payload["login_source"] = serde_json::json!("login");
    payload["login_canonical"] = serde_json::json!(canonical);
    payload["login_ip_hash"] = ip_hashes
        .first()
        .map_or(serde_json::Value::Null, |hash| serde_json::json!(hash));
    sqlx::query(
        "INSERT INTO login_tokens (purpose, token_hash, payload, expires_at) \
         VALUES ('magic_link', $1, $2, now() + make_interval(secs => $3))",
    )
    .bind(token_hash)
    .bind(payload)
    .bind(ttl.as_seconds_f64())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn create_session(
    pool: &PgPool,
    account_id: Uuid,
    session_hash: &[u8],
    ttl: Duration,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO sessions (account_id, session_hash, expires_at, last_seen_at) \
         VALUES ($1, $2, now() + make_interval(secs => $3), now()) RETURNING id",
    )
    .bind(account_id)
    .bind(session_hash)
    .bind(ttl.as_seconds_f64())
    .fetch_one(pool)
    .await
}

/// The account behind a live session. Refreshes `last_seen_at` at most every five minutes, so
/// page views don't each cost a write.
pub async fn find_session(
    pool: &PgPool,
    session_hash: &[u8],
) -> Result<Option<(Uuid, Account)>, sqlx::Error> {
    #[derive(FromRow)]
    struct Row {
        session_id: Uuid,
        stale: bool,
        id: Uuid,
        email: String,
        plan: String,
        is_owner: bool,
        github_id: Option<String>,
        created_at: time::OffsetDateTime,
    }
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT s.id AS session_id, \
                (s.last_seen_at IS NULL OR s.last_seen_at < now() - interval '5 minutes') AS stale, \
                {ACCOUNT_COLUMNS} \
         FROM sessions s JOIN accounts a ON a.id = s.account_id \
         WHERE s.session_hash = $1 AND s.expires_at > now()"
    ))
    .bind(session_hash)
    .fetch_optional(pool)
    .await?;
    let Some(r) = row else { return Ok(None) };
    if r.stale {
        sqlx::query("UPDATE sessions SET last_seen_at = now() WHERE id = $1")
            .bind(r.session_id)
            .execute(pool)
            .await?;
    }
    Ok(Some((
        r.session_id,
        Account {
            id: r.id,
            email: r.email,
            plan: crate::accounts::parse_plan(&r.plan),
            is_owner: r.is_owner,
            github_id: r.github_id,
            created_at: r.created_at,
        },
    )))
}

/// Ends a session (logout). Unknown hashes are a no-op.
pub async fn revoke_session(pool: &PgPool, session_hash: &[u8]) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE session_hash = $1")
        .bind(session_hash)
        .execute(pool)
        .await?;
    Ok(())
}
