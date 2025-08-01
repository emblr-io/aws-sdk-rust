// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The operation failed because the specified policy isn't in the proper format.</p>
/// <p>The policy specifications must conform to the following:</p>
/// <ul>
/// <li>
/// <p>The policy must be composed using IAM Policy version 2012-10-17.</p></li>
/// <li>
/// <p>The policy must include specifications for <code>Effect</code>, <code>Action</code>, and <code>Principal</code>.</p></li>
/// <li>
/// <p><code>Effect</code> must specify <code>Allow</code>.</p></li>
/// <li>
/// <p><code>Action</code> must specify <code>wafv2:CreateWebACL</code>, <code>wafv2:UpdateWebACL</code>, and <code>wafv2:PutFirewallManagerRuleGroups</code> and may optionally specify <code>wafv2:GetRuleGroup</code>. WAF rejects any extra actions or wildcard actions in the policy.</p></li>
/// <li>
/// <p>The policy must not include a <code>Resource</code> parameter.</p></li>
/// </ul>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html">IAM Policies</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WafInvalidPermissionPolicyException {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl WafInvalidPermissionPolicyException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for WafInvalidPermissionPolicyException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "WafInvalidPermissionPolicyException [WAFInvalidPermissionPolicyException]")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for WafInvalidPermissionPolicyException {}
impl ::aws_types::request_id::RequestId for crate::types::error::WafInvalidPermissionPolicyException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for WafInvalidPermissionPolicyException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl WafInvalidPermissionPolicyException {
    /// Creates a new builder-style object to manufacture [`WafInvalidPermissionPolicyException`](crate::types::error::WafInvalidPermissionPolicyException).
    pub fn builder() -> crate::types::error::builders::WafInvalidPermissionPolicyExceptionBuilder {
        crate::types::error::builders::WafInvalidPermissionPolicyExceptionBuilder::default()
    }
}

/// A builder for [`WafInvalidPermissionPolicyException`](crate::types::error::WafInvalidPermissionPolicyException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WafInvalidPermissionPolicyExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl WafInvalidPermissionPolicyExceptionBuilder {
    #[allow(missing_docs)] // documentation missing in model
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Sets error metadata
    pub fn meta(mut self, meta: ::aws_smithy_types::error::ErrorMetadata) -> Self {
        self.meta = Some(meta);
        self
    }

    /// Sets error metadata
    pub fn set_meta(&mut self, meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>) -> &mut Self {
        self.meta = meta;
        self
    }
    /// Consumes the builder and constructs a [`WafInvalidPermissionPolicyException`](crate::types::error::WafInvalidPermissionPolicyException).
    pub fn build(self) -> crate::types::error::WafInvalidPermissionPolicyException {
        crate::types::error::WafInvalidPermissionPolicyException {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
