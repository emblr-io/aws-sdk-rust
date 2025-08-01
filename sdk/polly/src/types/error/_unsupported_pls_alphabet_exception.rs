// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The alphabet specified by the lexicon is not a supported alphabet. Valid values are <code>x-sampa</code> and <code>ipa</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UnsupportedPlsAlphabetException {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl UnsupportedPlsAlphabetException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for UnsupportedPlsAlphabetException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "UnsupportedPlsAlphabetException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for UnsupportedPlsAlphabetException {}
impl ::aws_types::request_id::RequestId for crate::types::error::UnsupportedPlsAlphabetException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for UnsupportedPlsAlphabetException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl UnsupportedPlsAlphabetException {
    /// Creates a new builder-style object to manufacture [`UnsupportedPlsAlphabetException`](crate::types::error::UnsupportedPlsAlphabetException).
    pub fn builder() -> crate::types::error::builders::UnsupportedPlsAlphabetExceptionBuilder {
        crate::types::error::builders::UnsupportedPlsAlphabetExceptionBuilder::default()
    }
}

/// A builder for [`UnsupportedPlsAlphabetException`](crate::types::error::UnsupportedPlsAlphabetException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UnsupportedPlsAlphabetExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl UnsupportedPlsAlphabetExceptionBuilder {
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
    /// Consumes the builder and constructs a [`UnsupportedPlsAlphabetException`](crate::types::error::UnsupportedPlsAlphabetException).
    pub fn build(self) -> crate::types::error::UnsupportedPlsAlphabetException {
        crate::types::error::UnsupportedPlsAlphabetException {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
