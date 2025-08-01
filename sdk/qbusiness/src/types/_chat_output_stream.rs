// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The streaming output for the <code>Chat</code> API.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum ChatOutputStream {
    /// <p>A request from Amazon Q Business to the end user for information Amazon Q Business needs to successfully complete a requested plugin action.</p>
    ActionReviewEvent(crate::types::ActionReviewEvent),
    /// <p>An authentication verification event activated by an end user request to use a custom plugin.</p>
    AuthChallengeRequestEvent(crate::types::AuthChallengeRequestEvent),
    /// <p>A failed file upload event during a web experience chat.</p>
    FailedAttachmentEvent(crate::types::FailedAttachmentEvent),
    /// <p>A metadata event for a AI-generated text output message in a Amazon Q Business conversation.</p>
    MetadataEvent(crate::types::MetadataEvent),
    /// <p>Information about the payload of the <code>ChatOutputStream</code> event containing the AI-generated message output.</p>
    TextEvent(crate::types::TextOutputEvent),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl ChatOutputStream {
    /// Tries to convert the enum instance into [`ActionReviewEvent`](crate::types::ChatOutputStream::ActionReviewEvent), extracting the inner [`ActionReviewEvent`](crate::types::ActionReviewEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_action_review_event(&self) -> ::std::result::Result<&crate::types::ActionReviewEvent, &Self> {
        if let ChatOutputStream::ActionReviewEvent(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ActionReviewEvent`](crate::types::ChatOutputStream::ActionReviewEvent).
    pub fn is_action_review_event(&self) -> bool {
        self.as_action_review_event().is_ok()
    }
    /// Tries to convert the enum instance into [`AuthChallengeRequestEvent`](crate::types::ChatOutputStream::AuthChallengeRequestEvent), extracting the inner [`AuthChallengeRequestEvent`](crate::types::AuthChallengeRequestEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_auth_challenge_request_event(&self) -> ::std::result::Result<&crate::types::AuthChallengeRequestEvent, &Self> {
        if let ChatOutputStream::AuthChallengeRequestEvent(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`AuthChallengeRequestEvent`](crate::types::ChatOutputStream::AuthChallengeRequestEvent).
    pub fn is_auth_challenge_request_event(&self) -> bool {
        self.as_auth_challenge_request_event().is_ok()
    }
    /// Tries to convert the enum instance into [`FailedAttachmentEvent`](crate::types::ChatOutputStream::FailedAttachmentEvent), extracting the inner [`FailedAttachmentEvent`](crate::types::FailedAttachmentEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_failed_attachment_event(&self) -> ::std::result::Result<&crate::types::FailedAttachmentEvent, &Self> {
        if let ChatOutputStream::FailedAttachmentEvent(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`FailedAttachmentEvent`](crate::types::ChatOutputStream::FailedAttachmentEvent).
    pub fn is_failed_attachment_event(&self) -> bool {
        self.as_failed_attachment_event().is_ok()
    }
    /// Tries to convert the enum instance into [`MetadataEvent`](crate::types::ChatOutputStream::MetadataEvent), extracting the inner [`MetadataEvent`](crate::types::MetadataEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_metadata_event(&self) -> ::std::result::Result<&crate::types::MetadataEvent, &Self> {
        if let ChatOutputStream::MetadataEvent(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`MetadataEvent`](crate::types::ChatOutputStream::MetadataEvent).
    pub fn is_metadata_event(&self) -> bool {
        self.as_metadata_event().is_ok()
    }
    /// Tries to convert the enum instance into [`TextEvent`](crate::types::ChatOutputStream::TextEvent), extracting the inner [`TextOutputEvent`](crate::types::TextOutputEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_text_event(&self) -> ::std::result::Result<&crate::types::TextOutputEvent, &Self> {
        if let ChatOutputStream::TextEvent(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`TextEvent`](crate::types::ChatOutputStream::TextEvent).
    pub fn is_text_event(&self) -> bool {
        self.as_text_event().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
