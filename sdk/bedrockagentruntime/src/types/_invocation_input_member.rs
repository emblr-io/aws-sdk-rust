// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about the API operation or function that the agent predicts should be called.</p>
/// <p>This data type is used in the following API operations:</p>
/// <ul>
/// <li>
/// <p>In the <code>returnControl</code> field of the <a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_InvokeAgent.html#API_agent-runtime_InvokeAgent_ResponseSyntax">InvokeAgent response</a></p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum InvocationInputMember {
    /// <p>Contains information about the API operation that the agent predicts should be called.</p>
    ApiInvocationInput(crate::types::ApiInvocationInput),
    /// <p>Contains information about the function that the agent predicts should be called.</p>
    FunctionInvocationInput(crate::types::FunctionInvocationInput),
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
impl InvocationInputMember {
    /// Tries to convert the enum instance into [`ApiInvocationInput`](crate::types::InvocationInputMember::ApiInvocationInput), extracting the inner [`ApiInvocationInput`](crate::types::ApiInvocationInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_api_invocation_input(&self) -> ::std::result::Result<&crate::types::ApiInvocationInput, &Self> {
        if let InvocationInputMember::ApiInvocationInput(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ApiInvocationInput`](crate::types::InvocationInputMember::ApiInvocationInput).
    pub fn is_api_invocation_input(&self) -> bool {
        self.as_api_invocation_input().is_ok()
    }
    /// Tries to convert the enum instance into [`FunctionInvocationInput`](crate::types::InvocationInputMember::FunctionInvocationInput), extracting the inner [`FunctionInvocationInput`](crate::types::FunctionInvocationInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_function_invocation_input(&self) -> ::std::result::Result<&crate::types::FunctionInvocationInput, &Self> {
        if let InvocationInputMember::FunctionInvocationInput(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`FunctionInvocationInput`](crate::types::InvocationInputMember::FunctionInvocationInput).
    pub fn is_function_invocation_input(&self) -> bool {
        self.as_function_invocation_input().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
