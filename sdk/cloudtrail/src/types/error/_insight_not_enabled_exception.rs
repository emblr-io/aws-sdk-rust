// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>If you run <code>GetInsightSelectors</code> on a trail or event data store that does not have Insights events enabled, the operation throws the exception <code>InsightNotEnabledException</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InsightNotEnabledException {
    /// <p>Brief description of the exception returned by the request.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl InsightNotEnabledException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for InsightNotEnabledException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "InsightNotEnabledException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for InsightNotEnabledException {}
impl ::aws_types::request_id::RequestId for crate::types::error::InsightNotEnabledException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for InsightNotEnabledException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl InsightNotEnabledException {
    /// Creates a new builder-style object to manufacture [`InsightNotEnabledException`](crate::types::error::InsightNotEnabledException).
    pub fn builder() -> crate::types::error::builders::InsightNotEnabledExceptionBuilder {
        crate::types::error::builders::InsightNotEnabledExceptionBuilder::default()
    }
}

/// A builder for [`InsightNotEnabledException`](crate::types::error::InsightNotEnabledException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InsightNotEnabledExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl InsightNotEnabledExceptionBuilder {
    /// <p>Brief description of the exception returned by the request.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Brief description of the exception returned by the request.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>Brief description of the exception returned by the request.</p>
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
    /// Consumes the builder and constructs a [`InsightNotEnabledException`](crate::types::error::InsightNotEnabledException).
    pub fn build(self) -> crate::types::error::InsightNotEnabledException {
        crate::types::error::InsightNotEnabledException {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
