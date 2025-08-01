// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Returned if the access point that you are trying to create already exists, with the creation token you provided in the request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccessPointAlreadyExists {
    /// <p>The error code is a string that uniquely identifies an error condition. It is meant to be read and understood by programs that detect and handle errors by type.</p>
    pub error_code: ::std::string::String,
    /// <p>The error message contains a generic description of the error condition in English. It is intended for a human audience. Simple programs display the message directly to the end user if they encounter an error condition they don't know how or don't care to handle. Sophisticated programs with more exhaustive error handling and proper internationalization are more likely to ignore the error message.</p>
    pub message: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub access_point_id: ::std::string::String,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl AccessPointAlreadyExists {
    /// <p>The error code is a string that uniquely identifies an error condition. It is meant to be read and understood by programs that detect and handle errors by type.</p>
    pub fn error_code(&self) -> &str {
        use std::ops::Deref;
        self.error_code.deref()
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn access_point_id(&self) -> &str {
        use std::ops::Deref;
        self.access_point_id.deref()
    }
}
impl AccessPointAlreadyExists {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for AccessPointAlreadyExists {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "AccessPointAlreadyExists")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for AccessPointAlreadyExists {}
impl ::aws_types::request_id::RequestId for crate::types::error::AccessPointAlreadyExists {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for AccessPointAlreadyExists {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl AccessPointAlreadyExists {
    /// Creates a new builder-style object to manufacture [`AccessPointAlreadyExists`](crate::types::error::AccessPointAlreadyExists).
    pub fn builder() -> crate::types::error::builders::AccessPointAlreadyExistsBuilder {
        crate::types::error::builders::AccessPointAlreadyExistsBuilder::default()
    }
}

/// A builder for [`AccessPointAlreadyExists`](crate::types::error::AccessPointAlreadyExists).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccessPointAlreadyExistsBuilder {
    pub(crate) error_code: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) access_point_id: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl AccessPointAlreadyExistsBuilder {
    /// <p>The error code is a string that uniquely identifies an error condition. It is meant to be read and understood by programs that detect and handle errors by type.</p>
    /// This field is required.
    pub fn error_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error code is a string that uniquely identifies an error condition. It is meant to be read and understood by programs that detect and handle errors by type.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The error code is a string that uniquely identifies an error condition. It is meant to be read and understood by programs that detect and handle errors by type.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_code
    }
    /// <p>The error message contains a generic description of the error condition in English. It is intended for a human audience. Simple programs display the message directly to the end user if they encounter an error condition they don't know how or don't care to handle. Sophisticated programs with more exhaustive error handling and proper internationalization are more likely to ignore the error message.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error message contains a generic description of the error condition in English. It is intended for a human audience. Simple programs display the message directly to the end user if they encounter an error condition they don't know how or don't care to handle. Sophisticated programs with more exhaustive error handling and proper internationalization are more likely to ignore the error message.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The error message contains a generic description of the error condition in English. It is intended for a human audience. Simple programs display the message directly to the end user if they encounter an error condition they don't know how or don't care to handle. Sophisticated programs with more exhaustive error handling and proper internationalization are more likely to ignore the error message.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    #[allow(missing_docs)] // documentation missing in model
    /// This field is required.
    pub fn access_point_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.access_point_id = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_access_point_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.access_point_id = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_access_point_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.access_point_id
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
    /// Consumes the builder and constructs a [`AccessPointAlreadyExists`](crate::types::error::AccessPointAlreadyExists).
    /// This method will fail if any of the following fields are not set:
    /// - [`error_code`](crate::types::error::builders::AccessPointAlreadyExistsBuilder::error_code)
    /// - [`access_point_id`](crate::types::error::builders::AccessPointAlreadyExistsBuilder::access_point_id)
    pub fn build(self) -> ::std::result::Result<crate::types::error::AccessPointAlreadyExists, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::error::AccessPointAlreadyExists {
            error_code: self.error_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "error_code",
                    "error_code was not specified but it is required when building AccessPointAlreadyExists",
                )
            })?,
            message: self.message,
            access_point_id: self.access_point_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "access_point_id",
                    "access_point_id was not specified but it is required when building AccessPointAlreadyExists",
                )
            })?,
            meta: self.meta.unwrap_or_default(),
        })
    }
}
