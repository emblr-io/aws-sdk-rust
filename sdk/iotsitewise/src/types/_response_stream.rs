// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the response, citation, and trace from the SiteWise Assistant.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum ResponseStream {
    /// <p>Contains the SiteWise Assistant's response.</p>
    Output(crate::types::InvocationOutput),
    /// <p>Contains tracing information of the SiteWise Assistant's reasoning and data access.</p>
    Trace(crate::types::Trace),
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
    /// Tries to convert the enum instance into [`Output`](crate::types::ResponseStream::Output), extracting the inner [`InvocationOutput`](crate::types::InvocationOutput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_output(&self) -> ::std::result::Result<&crate::types::InvocationOutput, &Self> {
        if let ResponseStream::Output(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Output`](crate::types::ResponseStream::Output).
    pub fn is_output(&self) -> bool {
        self.as_output().is_ok()
    }
    /// Tries to convert the enum instance into [`Trace`](crate::types::ResponseStream::Trace), extracting the inner [`Trace`](crate::types::Trace).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_trace(&self) -> ::std::result::Result<&crate::types::Trace, &Self> {
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
