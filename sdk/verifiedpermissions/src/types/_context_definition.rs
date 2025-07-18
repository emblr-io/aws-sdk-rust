// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains additional details about the context of the request. Verified Permissions evaluates this information in an authorization request as part of the <code>when</code> and <code>unless</code> clauses in a policy.</p>
/// <p>This data type is used as a request parameter for the <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_IsAuthorized.html">IsAuthorized</a>, <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_BatchIsAuthorized.html">BatchIsAuthorized</a>, and <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_IsAuthorizedWithToken.html">IsAuthorizedWithToken</a> operations.</p>
/// <p>If you're passing context as part of the request, exactly one instance of <code>context</code> must be passed. If you don't want to pass context, omit the <code>context</code> parameter from your request rather than sending <code>context {}</code>.</p>
/// <p>Example: <code>"context":{"contextMap":{"&lt;KeyName1&gt;":{"boolean":true},"&lt;KeyName2&gt;":{"long":1234}}}</code></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub enum ContextDefinition {
    /// <p>A Cedar JSON string representation of the context needed to successfully evaluate an authorization request.</p>
    /// <p>Example: <code>{"cedarJson":"{\"&lt;KeyName1&gt;\": true, \"&lt;KeyName2&gt;\": 1234}" }</code></p>
    CedarJson(::std::string::String),
    /// <p>An list of attributes that are needed to successfully evaluate an authorization request. Each attribute in this array must include a map of a data type and its value.</p>
    /// <p>Example: <code>"contextMap":{"&lt;KeyName1&gt;":{"boolean":true},"&lt;KeyName2&gt;":{"long":1234}}</code></p>
    ContextMap(::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>),
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
impl ContextDefinition {
    /// Tries to convert the enum instance into [`CedarJson`](crate::types::ContextDefinition::CedarJson), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_cedar_json(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let ContextDefinition::CedarJson(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CedarJson`](crate::types::ContextDefinition::CedarJson).
    pub fn is_cedar_json(&self) -> bool {
        self.as_cedar_json().is_ok()
    }
    /// Tries to convert the enum instance into [`ContextMap`](crate::types::ContextDefinition::ContextMap), extracting the inner [`HashMap`](::std::collections::HashMap).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_context_map(&self) -> ::std::result::Result<&::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>, &Self> {
        if let ContextDefinition::ContextMap(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ContextMap`](crate::types::ContextDefinition::ContextMap).
    pub fn is_context_map(&self) -> bool {
        self.as_context_map().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
impl ::std::fmt::Debug for ContextDefinition {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match self {
            ContextDefinition::CedarJson(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            ContextDefinition::ContextMap(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            ContextDefinition::Unknown => f.debug_tuple("Unknown").finish(),
        }
    }
}
