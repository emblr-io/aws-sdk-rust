// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The specified DB shard group name must be unique in your Amazon Web Services account in the specified Amazon Web Services Region.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DbShardGroupAlreadyExistsFault {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl DbShardGroupAlreadyExistsFault {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for DbShardGroupAlreadyExistsFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "DbShardGroupAlreadyExistsFault [DBShardGroupAlreadyExistsFault]")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for DbShardGroupAlreadyExistsFault {}
impl ::aws_types::request_id::RequestId for crate::types::error::DbShardGroupAlreadyExistsFault {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for DbShardGroupAlreadyExistsFault {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl DbShardGroupAlreadyExistsFault {
    /// Creates a new builder-style object to manufacture [`DbShardGroupAlreadyExistsFault`](crate::types::error::DbShardGroupAlreadyExistsFault).
    pub fn builder() -> crate::types::error::builders::DbShardGroupAlreadyExistsFaultBuilder {
        crate::types::error::builders::DbShardGroupAlreadyExistsFaultBuilder::default()
    }
}

/// A builder for [`DbShardGroupAlreadyExistsFault`](crate::types::error::DbShardGroupAlreadyExistsFault).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DbShardGroupAlreadyExistsFaultBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl DbShardGroupAlreadyExistsFaultBuilder {
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
    /// Consumes the builder and constructs a [`DbShardGroupAlreadyExistsFault`](crate::types::error::DbShardGroupAlreadyExistsFault).
    pub fn build(self) -> crate::types::error::DbShardGroupAlreadyExistsFault {
        crate::types::error::DbShardGroupAlreadyExistsFault {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
