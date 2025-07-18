// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The <code>PutResourcePolicy</code> API action enforces two limits. A policy can't be greater than 1024 bytes in size. And only one policy can be attached to <code>OpsItemGroup</code>. Verify these limits and try again.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourcePolicyLimitExceededException {
    #[allow(missing_docs)] // documentation missing in model
    pub limit: i32,
    #[allow(missing_docs)] // documentation missing in model
    pub limit_type: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl ResourcePolicyLimitExceededException {
    #[allow(missing_docs)] // documentation missing in model
    pub fn limit(&self) -> i32 {
        self.limit
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn limit_type(&self) -> ::std::option::Option<&str> {
        self.limit_type.as_deref()
    }
}
impl ResourcePolicyLimitExceededException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for ResourcePolicyLimitExceededException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "ResourcePolicyLimitExceededException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for ResourcePolicyLimitExceededException {}
impl ::aws_types::request_id::RequestId for crate::types::error::ResourcePolicyLimitExceededException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for ResourcePolicyLimitExceededException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl ResourcePolicyLimitExceededException {
    /// Creates a new builder-style object to manufacture [`ResourcePolicyLimitExceededException`](crate::types::error::ResourcePolicyLimitExceededException).
    pub fn builder() -> crate::types::error::builders::ResourcePolicyLimitExceededExceptionBuilder {
        crate::types::error::builders::ResourcePolicyLimitExceededExceptionBuilder::default()
    }
}

/// A builder for [`ResourcePolicyLimitExceededException`](crate::types::error::ResourcePolicyLimitExceededException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourcePolicyLimitExceededExceptionBuilder {
    pub(crate) limit: ::std::option::Option<i32>,
    pub(crate) limit_type: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl ResourcePolicyLimitExceededExceptionBuilder {
    #[allow(missing_docs)] // documentation missing in model
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn limit_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.limit_type = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_limit_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.limit_type = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_limit_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.limit_type
    }
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
    /// Consumes the builder and constructs a [`ResourcePolicyLimitExceededException`](crate::types::error::ResourcePolicyLimitExceededException).
    pub fn build(self) -> crate::types::error::ResourcePolicyLimitExceededException {
        crate::types::error::ResourcePolicyLimitExceededException {
            limit: self.limit.unwrap_or_default(),
            limit_type: self.limit_type,
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
