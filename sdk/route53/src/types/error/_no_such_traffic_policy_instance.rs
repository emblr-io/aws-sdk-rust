// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>No traffic policy instance exists with the specified ID.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NoSuchTrafficPolicyInstance {
    /// <p></p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl NoSuchTrafficPolicyInstance {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for NoSuchTrafficPolicyInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "NoSuchTrafficPolicyInstance")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for NoSuchTrafficPolicyInstance {}
impl ::aws_types::request_id::RequestId for crate::types::error::NoSuchTrafficPolicyInstance {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for NoSuchTrafficPolicyInstance {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl NoSuchTrafficPolicyInstance {
    /// Creates a new builder-style object to manufacture [`NoSuchTrafficPolicyInstance`](crate::types::error::NoSuchTrafficPolicyInstance).
    pub fn builder() -> crate::types::error::builders::NoSuchTrafficPolicyInstanceBuilder {
        crate::types::error::builders::NoSuchTrafficPolicyInstanceBuilder::default()
    }
}

/// A builder for [`NoSuchTrafficPolicyInstance`](crate::types::error::NoSuchTrafficPolicyInstance).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NoSuchTrafficPolicyInstanceBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl NoSuchTrafficPolicyInstanceBuilder {
    /// <p></p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p></p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p></p>
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
    /// Consumes the builder and constructs a [`NoSuchTrafficPolicyInstance`](crate::types::error::NoSuchTrafficPolicyInstance).
    pub fn build(self) -> crate::types::error::NoSuchTrafficPolicyInstance {
        crate::types::error::NoSuchTrafficPolicyInstance {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
