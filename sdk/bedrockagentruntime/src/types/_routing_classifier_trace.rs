// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A trace for a routing classifier.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub enum RoutingClassifierTrace {
    /// <p>The classifier's invocation input.</p>
    InvocationInput(crate::types::InvocationInput),
    /// <p>The classifier's model invocation input.</p>
    ModelInvocationInput(crate::types::ModelInvocationInput),
    /// <p>The classifier's model invocation output.</p>
    ModelInvocationOutput(crate::types::RoutingClassifierModelInvocationOutput),
    /// <p>The classifier's observation.</p>
    Observation(crate::types::Observation),
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
impl RoutingClassifierTrace {
    /// Tries to convert the enum instance into [`InvocationInput`](crate::types::RoutingClassifierTrace::InvocationInput), extracting the inner [`InvocationInput`](crate::types::InvocationInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_invocation_input(&self) -> ::std::result::Result<&crate::types::InvocationInput, &Self> {
        if let RoutingClassifierTrace::InvocationInput(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`InvocationInput`](crate::types::RoutingClassifierTrace::InvocationInput).
    pub fn is_invocation_input(&self) -> bool {
        self.as_invocation_input().is_ok()
    }
    /// Tries to convert the enum instance into [`ModelInvocationInput`](crate::types::RoutingClassifierTrace::ModelInvocationInput), extracting the inner [`ModelInvocationInput`](crate::types::ModelInvocationInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_model_invocation_input(&self) -> ::std::result::Result<&crate::types::ModelInvocationInput, &Self> {
        if let RoutingClassifierTrace::ModelInvocationInput(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ModelInvocationInput`](crate::types::RoutingClassifierTrace::ModelInvocationInput).
    pub fn is_model_invocation_input(&self) -> bool {
        self.as_model_invocation_input().is_ok()
    }
    /// Tries to convert the enum instance into [`ModelInvocationOutput`](crate::types::RoutingClassifierTrace::ModelInvocationOutput), extracting the inner [`RoutingClassifierModelInvocationOutput`](crate::types::RoutingClassifierModelInvocationOutput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_model_invocation_output(&self) -> ::std::result::Result<&crate::types::RoutingClassifierModelInvocationOutput, &Self> {
        if let RoutingClassifierTrace::ModelInvocationOutput(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ModelInvocationOutput`](crate::types::RoutingClassifierTrace::ModelInvocationOutput).
    pub fn is_model_invocation_output(&self) -> bool {
        self.as_model_invocation_output().is_ok()
    }
    /// Tries to convert the enum instance into [`Observation`](crate::types::RoutingClassifierTrace::Observation), extracting the inner [`Observation`](crate::types::Observation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_observation(&self) -> ::std::result::Result<&crate::types::Observation, &Self> {
        if let RoutingClassifierTrace::Observation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Observation`](crate::types::RoutingClassifierTrace::Observation).
    pub fn is_observation(&self) -> bool {
        self.as_observation().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
impl ::std::fmt::Debug for RoutingClassifierTrace {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::std::write!(f, "*** Sensitive Data Redacted ***")
    }
}
