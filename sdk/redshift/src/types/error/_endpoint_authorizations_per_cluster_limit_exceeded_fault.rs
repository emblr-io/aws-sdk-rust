// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The number of endpoint authorizations per cluster has exceeded its limit.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EndpointAuthorizationsPerClusterLimitExceededFault {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl EndpointAuthorizationsPerClusterLimitExceededFault {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for EndpointAuthorizationsPerClusterLimitExceededFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "EndpointAuthorizationsPerClusterLimitExceededFault")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for EndpointAuthorizationsPerClusterLimitExceededFault {}
impl ::aws_types::request_id::RequestId for crate::types::error::EndpointAuthorizationsPerClusterLimitExceededFault {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for EndpointAuthorizationsPerClusterLimitExceededFault {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl EndpointAuthorizationsPerClusterLimitExceededFault {
    /// Creates a new builder-style object to manufacture [`EndpointAuthorizationsPerClusterLimitExceededFault`](crate::types::error::EndpointAuthorizationsPerClusterLimitExceededFault).
    pub fn builder() -> crate::types::error::builders::EndpointAuthorizationsPerClusterLimitExceededFaultBuilder {
        crate::types::error::builders::EndpointAuthorizationsPerClusterLimitExceededFaultBuilder::default()
    }
}

/// A builder for [`EndpointAuthorizationsPerClusterLimitExceededFault`](crate::types::error::EndpointAuthorizationsPerClusterLimitExceededFault).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EndpointAuthorizationsPerClusterLimitExceededFaultBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl EndpointAuthorizationsPerClusterLimitExceededFaultBuilder {
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
    /// Consumes the builder and constructs a [`EndpointAuthorizationsPerClusterLimitExceededFault`](crate::types::error::EndpointAuthorizationsPerClusterLimitExceededFault).
    pub fn build(self) -> crate::types::error::EndpointAuthorizationsPerClusterLimitExceededFault {
        crate::types::error::EndpointAuthorizationsPerClusterLimitExceededFault {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
