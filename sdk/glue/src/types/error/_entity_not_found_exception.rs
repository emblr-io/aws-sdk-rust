// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A specified entity does not exist</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EntityNotFoundException {
    /// <p>A message describing the problem.</p>
    pub message: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether or not the exception relates to a federated source.</p>
    pub from_federation_source: ::std::option::Option<bool>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl EntityNotFoundException {
    /// <p>Indicates whether or not the exception relates to a federated source.</p>
    pub fn from_federation_source(&self) -> ::std::option::Option<bool> {
        self.from_federation_source
    }
}
impl EntityNotFoundException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for EntityNotFoundException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "EntityNotFoundException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for EntityNotFoundException {}
impl ::aws_types::request_id::RequestId for crate::types::error::EntityNotFoundException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for EntityNotFoundException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl EntityNotFoundException {
    /// Creates a new builder-style object to manufacture [`EntityNotFoundException`](crate::types::error::EntityNotFoundException).
    pub fn builder() -> crate::types::error::builders::EntityNotFoundExceptionBuilder {
        crate::types::error::builders::EntityNotFoundExceptionBuilder::default()
    }
}

/// A builder for [`EntityNotFoundException`](crate::types::error::EntityNotFoundException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EntityNotFoundExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) from_federation_source: ::std::option::Option<bool>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl EntityNotFoundExceptionBuilder {
    /// <p>A message describing the problem.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message describing the problem.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message describing the problem.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>Indicates whether or not the exception relates to a federated source.</p>
    pub fn from_federation_source(mut self, input: bool) -> Self {
        self.from_federation_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether or not the exception relates to a federated source.</p>
    pub fn set_from_federation_source(mut self, input: ::std::option::Option<bool>) -> Self {
        self.from_federation_source = input;
        self
    }
    /// <p>Indicates whether or not the exception relates to a federated source.</p>
    pub fn get_from_federation_source(&self) -> &::std::option::Option<bool> {
        &self.from_federation_source
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
    /// Consumes the builder and constructs a [`EntityNotFoundException`](crate::types::error::EntityNotFoundException).
    pub fn build(self) -> crate::types::error::EntityNotFoundException {
        crate::types::error::EntityNotFoundException {
            message: self.message,
            from_federation_source: self.from_federation_source,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
