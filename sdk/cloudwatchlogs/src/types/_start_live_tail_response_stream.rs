// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This object includes the stream returned by your <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_StartLiveTail.html">StartLiveTail</a> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum StartLiveTailResponseStream {
    /// <p>This object contains information about this Live Tail session, including the log groups included and the log stream filters, if any.</p>
    SessionStart(crate::types::LiveTailSessionStart),
    /// <p>This object contains the log events and session metadata.</p>
    SessionUpdate(crate::types::LiveTailSessionUpdate),
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
impl StartLiveTailResponseStream {
    /// Tries to convert the enum instance into [`SessionStart`](crate::types::StartLiveTailResponseStream::SessionStart), extracting the inner [`LiveTailSessionStart`](crate::types::LiveTailSessionStart).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_session_start(&self) -> ::std::result::Result<&crate::types::LiveTailSessionStart, &Self> {
        if let StartLiveTailResponseStream::SessionStart(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`SessionStart`](crate::types::StartLiveTailResponseStream::SessionStart).
    pub fn is_session_start(&self) -> bool {
        self.as_session_start().is_ok()
    }
    /// Tries to convert the enum instance into [`SessionUpdate`](crate::types::StartLiveTailResponseStream::SessionUpdate), extracting the inner [`LiveTailSessionUpdate`](crate::types::LiveTailSessionUpdate).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_session_update(&self) -> ::std::result::Result<&crate::types::LiveTailSessionUpdate, &Self> {
        if let StartLiveTailResponseStream::SessionUpdate(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`SessionUpdate`](crate::types::StartLiveTailResponseStream::SessionUpdate).
    pub fn is_session_update(&self) -> bool {
        self.as_session_update().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
