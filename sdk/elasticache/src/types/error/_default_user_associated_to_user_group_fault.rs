// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The default user assigned to the user group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DefaultUserAssociatedToUserGroupFault {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl DefaultUserAssociatedToUserGroupFault {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for DefaultUserAssociatedToUserGroupFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "DefaultUserAssociatedToUserGroupFault")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for DefaultUserAssociatedToUserGroupFault {}
impl ::aws_types::request_id::RequestId for crate::types::error::DefaultUserAssociatedToUserGroupFault {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for DefaultUserAssociatedToUserGroupFault {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl DefaultUserAssociatedToUserGroupFault {
    /// Creates a new builder-style object to manufacture [`DefaultUserAssociatedToUserGroupFault`](crate::types::error::DefaultUserAssociatedToUserGroupFault).
    pub fn builder() -> crate::types::error::builders::DefaultUserAssociatedToUserGroupFaultBuilder {
        crate::types::error::builders::DefaultUserAssociatedToUserGroupFaultBuilder::default()
    }
}

/// A builder for [`DefaultUserAssociatedToUserGroupFault`](crate::types::error::DefaultUserAssociatedToUserGroupFault).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DefaultUserAssociatedToUserGroupFaultBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl DefaultUserAssociatedToUserGroupFaultBuilder {
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
    /// Consumes the builder and constructs a [`DefaultUserAssociatedToUserGroupFault`](crate::types::error::DefaultUserAssociatedToUserGroupFault).
    pub fn build(self) -> crate::types::error::DefaultUserAssociatedToUserGroupFault {
        crate::types::error::DefaultUserAssociatedToUserGroupFault {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
