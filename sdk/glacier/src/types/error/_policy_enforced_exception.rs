// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Returned if a retrieval job would exceed the current data policy's retrieval rate limit. For more information about data retrieval policies,</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PolicyEnforcedException {
    /// <p>Client</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>PolicyEnforcedException</p>
    pub code: ::std::option::Option<::std::string::String>,
    /// <p>InitiateJob request denied by current data retrieval policy.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl PolicyEnforcedException {
    /// <p>Client</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>PolicyEnforcedException</p>
    pub fn code(&self) -> ::std::option::Option<&str> {
        self.code.as_deref()
    }
}
impl PolicyEnforcedException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for PolicyEnforcedException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "PolicyEnforcedException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for PolicyEnforcedException {}
impl ::aws_types::request_id::RequestId for crate::types::error::PolicyEnforcedException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for PolicyEnforcedException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl PolicyEnforcedException {
    /// Creates a new builder-style object to manufacture [`PolicyEnforcedException`](crate::types::error::PolicyEnforcedException).
    pub fn builder() -> crate::types::error::builders::PolicyEnforcedExceptionBuilder {
        crate::types::error::builders::PolicyEnforcedExceptionBuilder::default()
    }
}

/// A builder for [`PolicyEnforcedException`](crate::types::error::PolicyEnforcedException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PolicyEnforcedExceptionBuilder {
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) code: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl PolicyEnforcedExceptionBuilder {
    /// <p>Client</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Client</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Client</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>PolicyEnforcedException</p>
    pub fn code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>PolicyEnforcedException</p>
    pub fn set_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code = input;
        self
    }
    /// <p>PolicyEnforcedException</p>
    pub fn get_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.code
    }
    /// <p>InitiateJob request denied by current data retrieval policy.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>InitiateJob request denied by current data retrieval policy.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>InitiateJob request denied by current data retrieval policy.</p>
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
    /// Consumes the builder and constructs a [`PolicyEnforcedException`](crate::types::error::PolicyEnforcedException).
    pub fn build(self) -> crate::types::error::PolicyEnforcedException {
        crate::types::error::PolicyEnforcedException {
            r#type: self.r#type,
            code: self.code,
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
