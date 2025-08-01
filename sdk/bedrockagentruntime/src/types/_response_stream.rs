// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The response from invoking the agent and associated citations and trace information.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub enum ResponseStream {
    /// <p>Contains a part of an agent response and citations for it.</p>
    Chunk(crate::types::PayloadPart),
    /// <p>Contains intermediate response for code interpreter if any files have been generated.</p>
    Files(crate::types::FilePart),
    /// <p>Contains the parameters and information that the agent elicited from the customer to carry out an action. This information is returned to the system and can be used in your own setup for fulfilling the action.</p>
    ReturnControl(crate::types::ReturnControlPayload),
    /// <p>Contains information about the agent and session, alongside the agent's reasoning process and results from calling actions and querying knowledge bases and metadata about the trace. You can use the trace to understand how the agent arrived at the response it provided the customer. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/trace-events.html">Trace events</a>.</p>
    Trace(crate::types::TracePart),
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
impl ResponseStream {
    /// Tries to convert the enum instance into [`Chunk`](crate::types::ResponseStream::Chunk), extracting the inner [`PayloadPart`](crate::types::PayloadPart).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_chunk(&self) -> ::std::result::Result<&crate::types::PayloadPart, &Self> {
        if let ResponseStream::Chunk(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Chunk`](crate::types::ResponseStream::Chunk).
    pub fn is_chunk(&self) -> bool {
        self.as_chunk().is_ok()
    }
    /// Tries to convert the enum instance into [`Files`](crate::types::ResponseStream::Files), extracting the inner [`FilePart`](crate::types::FilePart).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_files(&self) -> ::std::result::Result<&crate::types::FilePart, &Self> {
        if let ResponseStream::Files(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Files`](crate::types::ResponseStream::Files).
    pub fn is_files(&self) -> bool {
        self.as_files().is_ok()
    }
    /// Tries to convert the enum instance into [`ReturnControl`](crate::types::ResponseStream::ReturnControl), extracting the inner [`ReturnControlPayload`](crate::types::ReturnControlPayload).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_return_control(&self) -> ::std::result::Result<&crate::types::ReturnControlPayload, &Self> {
        if let ResponseStream::ReturnControl(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ReturnControl`](crate::types::ResponseStream::ReturnControl).
    pub fn is_return_control(&self) -> bool {
        self.as_return_control().is_ok()
    }
    /// Tries to convert the enum instance into [`Trace`](crate::types::ResponseStream::Trace), extracting the inner [`TracePart`](crate::types::TracePart).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_trace(&self) -> ::std::result::Result<&crate::types::TracePart, &Self> {
        if let ResponseStream::Trace(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Trace`](crate::types::ResponseStream::Trace).
    pub fn is_trace(&self) -> bool {
        self.as_trace().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
impl ::std::fmt::Debug for ResponseStream {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match self {
            ResponseStream::Chunk(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            ResponseStream::Files(val) => f.debug_tuple("Files").field(&val).finish(),
            ResponseStream::ReturnControl(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            ResponseStream::Trace(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            ResponseStream::Unknown => f.debug_tuple("Unknown").finish(),
        }
    }
}
