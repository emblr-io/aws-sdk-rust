// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The operation conflicts with the resource's availability. For example:</p>
/// <ul>
/// <li>
/// <p>You attempted to recreate an existing table.</p></li>
/// <li>
/// <p>You tried to delete a table currently in the <code>CREATING</code> state.</p></li>
/// <li>
/// <p>You tried to update a resource that was already being updated.</p></li>
/// </ul>
/// <p>When appropriate, wait for the ongoing update to complete and attempt the request again.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceInUseException {
    /// <p>The resource which is being attempted to be changed is in use.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl ResourceInUseException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for ResourceInUseException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "ResourceInUseException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for ResourceInUseException {}
impl ::aws_types::request_id::RequestId for crate::types::error::ResourceInUseException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for ResourceInUseException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl ResourceInUseException {
    /// Creates a new builder-style object to manufacture [`ResourceInUseException`](crate::types::error::ResourceInUseException).
    pub fn builder() -> crate::types::error::builders::ResourceInUseExceptionBuilder {
        crate::types::error::builders::ResourceInUseExceptionBuilder::default()
    }
}

/// A builder for [`ResourceInUseException`](crate::types::error::ResourceInUseException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceInUseExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl ResourceInUseExceptionBuilder {
    /// <p>The resource which is being attempted to be changed is in use.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resource which is being attempted to be changed is in use.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The resource which is being attempted to be changed is in use.</p>
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
    /// Consumes the builder and constructs a [`ResourceInUseException`](crate::types::error::ResourceInUseException).
    pub fn build(self) -> crate::types::error::ResourceInUseException {
        crate::types::error::ResourceInUseException {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
