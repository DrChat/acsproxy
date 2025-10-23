use std::sync::Arc;

use anyhow::Context;
use azure_core::auth::TokenCredential;
use serde::{Deserialize, Serialize};
use url::Url;

/// Represents an email address with optional display name
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailAddress {
    /// Email address
    pub address: String,
    /// Optional email display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Email content
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailContent {
    /// Subject of the email
    pub subject: String,
    /// Plain text version of the email message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plain_text: Option<String>,
    /// HTML version of the email message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
}

/// Recipients for the email
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EmailRecipients {
    /// Email To recipients
    pub to: Vec<EmailAddress>,
    /// Email CC recipients
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<Vec<EmailAddress>>,
    /// Email BCC recipients
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bcc: Option<Vec<EmailAddress>>,
}

/// Attachment to the email
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailAttachment {
    /// Name of the attachment
    pub name: String,
    /// MIME type of the content being attached
    pub content_type: String,
    /// Base64 encoded contents of the attachment
    pub content_in_base64: String,
    /// Unique identifier (CID) to reference an inline attachment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_id: Option<String>,
}

/// Message payload for sending an email
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailMessage {
    /// Sender email address from a verified domain
    pub sender_address: String,
    /// Email content to be sent
    pub content: EmailContent,
    /// Recipients for the email
    pub recipients: EmailRecipients,
    /// Custom email headers to be passed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<std::collections::HashMap<String, String>>,
    /// List of attachments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<EmailAttachment>>,
    /// Email addresses where recipients' replies will be sent to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<Vec<EmailAddress>>,
    /// Indicates whether user engagement tracking should be disabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_engagement_tracking_disabled: Option<bool>,
}

/// Status of the email send operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum EmailSendStatus {
    NotStarted,
    Running,
    Succeeded,
    Failed,
    Canceled,
}

/// The resource management error additional info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorAdditionalInfo {
    /// The additional info type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// The additional info (stored as generic JSON)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<serde_json::Value>,
}

/// The error detail
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorDetail {
    /// The error code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// The error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The error target
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The error details (can be recursive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<ErrorDetail>>,
    /// The error additional info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_info: Option<Vec<ErrorAdditionalInfo>>,
}

/// Error response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    /// The error object
    pub error: ErrorDetail,
}

/// Response from the send email API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSendResult {
    /// The unique id of the operation
    pub id: String,
    /// Status of operation
    pub status: EmailSendStatus,
    /// Error details when status is a non-success terminal state
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDetail>,
}

/// Sends an email using Azure Communication Services
///
/// # Arguments
/// * `endpoint` - The ACS endpoint URL (e.g., https://my-resource.communication.azure.com)
/// * `email` - The email message to send
/// * `credential` - Azure credential for authentication
///
/// # Returns
/// The operation ID and initial status from the send operation
pub async fn send_email(
    endpoint: &Url,
    email: EmailMessage,
    credential: Arc<dyn TokenCredential>,
) -> anyhow::Result<EmailSendResult> {
    const API_VERSION: &str = "api-version=2025-09-01";

    // Construct the API endpoint URL
    let mut url = endpoint.clone();
    url.set_path("/emails:send");
    url.set_query(Some(API_VERSION));

    // Get an access token for Communication Services
    let token_response = credential
        .get_token(&["https://communication.azure.com/.default"])
        .await
        .context("failed to acquire access token")?;

    // Build and send the HTTP request
    let client = reqwest::Client::new();
    let response = client
        .post(url.as_str())
        .header(
            "Authorization",
            format!("Bearer {}", token_response.token.secret()),
        )
        .header("Content-Type", "application/json")
        .json(&email)
        .send()
        .await
        .context("failed to send email request")?;

    // Check if the request was accepted
    if response.status() != reqwest::StatusCode::ACCEPTED {
        let result: ErrorResponse = response
            .json()
            .await
            .context("failed to parse email send result")?;

        anyhow::bail!(
            "{}: {}",
            result.error.code.as_deref().unwrap_or("<unk>"),
            result.error.message.as_deref().unwrap_or("<unk>"),
        );
    }

    // Parse the response body
    let result: EmailSendResult = response
        .json()
        .await
        .context("failed to parse email send result")?;

    Ok(result)
}

/// Waits for an email send operation to complete by polling the status API
///
/// This function polls the Azure Communication Services API until the email
/// operation reaches a terminal status (Succeeded, Failed, or Canceled).
///
/// # Arguments
/// * `endpoint` - The ACS endpoint URL (e.g., https://my-resource.communication.azure.com)
/// * `result` - The initial EmailSendResult from send_email
/// * `credential` - Azure credential for authentication
///
/// # Returns
/// The final EmailSendResult when the operation reaches a terminal status (Succeeded, Failed, or Canceled)
///
/// # Example
/// ```no_run
/// # use acsproxy::{send_email, wait_email, EmailAddress, EmailContent, EmailMessage, EmailRecipients};
/// # use std::sync::Arc;
/// # use url::Url;
/// # async fn example() -> anyhow::Result<()> {
/// # let credential = Arc::new(azure_identity::create_default_credential().unwrap());
/// # let endpoint = Url::parse("https://my-resource.communication.azure.com")?;
/// # let email = EmailMessage {
/// #     sender_address: "test@example.com".to_string(),
/// #     content: EmailContent { subject: "Test".to_string(), plain_text: None, html: None },
/// #     recipients: EmailRecipients::default(),
/// #     headers: None,
/// #     attachments: None,
/// #     reply_to: None,
/// #     user_engagement_tracking_disabled: None,
/// # };
/// let result = send_email(&endpoint, email, credential.clone()).await?;
/// let final_result = wait_email(&endpoint, result, credential).await?;
///
/// match final_result.status {
///     EmailSendStatus::Succeeded => println!("Email sent successfully!"),
///     EmailSendStatus::Failed => println!("Email failed to send"),
///     _ => println!("Email operation was canceled"),
/// }
/// # Ok(())
/// # }
/// ```
pub async fn wait_email(
    endpoint: &Url,
    mut result: EmailSendResult,
    credential: Arc<dyn TokenCredential>,
) -> anyhow::Result<EmailSendResult> {
    const API_VERSION: &str = "api-version=2025-09-01";

    let client = reqwest::Client::new();

    // Poll until we reach a terminal status
    loop {
        // Construct the API endpoint URL
        let mut url = endpoint.clone();
        url.set_path(&format!("/emails/operations/{}", result.id));
        url.set_query(Some(API_VERSION));

        // Get an access token for Communication Services
        let token_response = credential
            .get_token(&["https://communication.azure.com/.default"])
            .await
            .context("failed to acquire access token")?;

        // Build and send the HTTP request
        let response = client
            .get(url.as_str())
            .header(
                "Authorization",
                format!("Bearer {}", token_response.token.secret()),
            )
            .send()
            .await
            .context("failed to get email status")?;

        // Check if the request was successful
        if response.status() != reqwest::StatusCode::OK {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Get email status request failed with status {}: {}",
                status,
                error_body
            );
        }

        // Check for retry-after header to determine next poll interval (if present)
        let retry_after_secs = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1);

        // Parse the response body
        result = response
            .json()
            .await
            .context("failed to parse email send result")?;

        tracing::debug!("{:?}", result);
        match result.status {
            EmailSendStatus::NotStarted | EmailSendStatus::Running => {
                tokio::time::sleep(tokio::time::Duration::from_secs(retry_after_secs)).await;
            }
            EmailSendStatus::Succeeded | EmailSendStatus::Failed | EmailSendStatus::Canceled => {
                return Ok(result);
            }
        }
    }
}
