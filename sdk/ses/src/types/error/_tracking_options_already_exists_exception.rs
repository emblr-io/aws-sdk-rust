// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Indicates that the configuration set you specified already contains a TrackingOptions object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TrackingOptionsAlreadyExistsException {
    /// <p>Indicates that a TrackingOptions object already exists in the specified configuration set.</p>
    pub configuration_set_name: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl TrackingOptionsAlreadyExistsException {
    /// <p>Indicates that a TrackingOptions object already exists in the specified configuration set.</p>
    pub fn configuration_set_name(&self) -> ::std::option::Option<&str> {
        self.configuration_set_name.as_deref()
    }
}
impl TrackingOptionsAlreadyExistsException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for TrackingOptionsAlreadyExistsException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "TrackingOptionsAlreadyExistsException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for TrackingOptionsAlreadyExistsException {}
impl ::aws_types::request_id::RequestId for crate::types::error::TrackingOptionsAlreadyExistsException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for TrackingOptionsAlreadyExistsException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl TrackingOptionsAlreadyExistsException {
    /// Creates a new builder-style object to manufacture [`TrackingOptionsAlreadyExistsException`](crate::types::error::TrackingOptionsAlreadyExistsException).
    pub fn builder() -> crate::types::error::builders::TrackingOptionsAlreadyExistsExceptionBuilder {
        crate::types::error::builders::TrackingOptionsAlreadyExistsExceptionBuilder::default()
    }
}

/// A builder for [`TrackingOptionsAlreadyExistsException`](crate::types::error::TrackingOptionsAlreadyExistsException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TrackingOptionsAlreadyExistsExceptionBuilder {
    pub(crate) configuration_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl TrackingOptionsAlreadyExistsExceptionBuilder {
    /// <p>Indicates that a TrackingOptions object already exists in the specified configuration set.</p>
    pub fn configuration_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates that a TrackingOptions object already exists in the specified configuration set.</p>
    pub fn set_configuration_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_set_name = input;
        self
    }
    /// <p>Indicates that a TrackingOptions object already exists in the specified configuration set.</p>
    pub fn get_configuration_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_set_name
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
    /// Consumes the builder and constructs a [`TrackingOptionsAlreadyExistsException`](crate::types::error::TrackingOptionsAlreadyExistsException).
    pub fn build(self) -> crate::types::error::TrackingOptionsAlreadyExistsException {
        crate::types::error::TrackingOptionsAlreadyExistsException {
            configuration_set_name: self.configuration_set_name,
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
