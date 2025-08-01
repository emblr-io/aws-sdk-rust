// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Returned if the type already exists in the specified domain. You may get this fault if you are registering a type that is either already registered or deprecated, or if you undeprecate a type that is currently registered.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TypeAlreadyExistsFault {
    /// <p>A description that may help with diagnosing the cause of the fault.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl TypeAlreadyExistsFault {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for TypeAlreadyExistsFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "TypeAlreadyExistsFault")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for TypeAlreadyExistsFault {}
impl ::aws_types::request_id::RequestId for crate::types::error::TypeAlreadyExistsFault {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for TypeAlreadyExistsFault {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl TypeAlreadyExistsFault {
    /// Creates a new builder-style object to manufacture [`TypeAlreadyExistsFault`](crate::types::error::TypeAlreadyExistsFault).
    pub fn builder() -> crate::types::error::builders::TypeAlreadyExistsFaultBuilder {
        crate::types::error::builders::TypeAlreadyExistsFaultBuilder::default()
    }
}

/// A builder for [`TypeAlreadyExistsFault`](crate::types::error::TypeAlreadyExistsFault).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TypeAlreadyExistsFaultBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl TypeAlreadyExistsFaultBuilder {
    /// <p>A description that may help with diagnosing the cause of the fault.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description that may help with diagnosing the cause of the fault.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A description that may help with diagnosing the cause of the fault.</p>
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
    /// Consumes the builder and constructs a [`TypeAlreadyExistsFault`](crate::types::error::TypeAlreadyExistsFault).
    pub fn build(self) -> crate::types::error::TypeAlreadyExistsFault {
        crate::types::error::TypeAlreadyExistsFault {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
