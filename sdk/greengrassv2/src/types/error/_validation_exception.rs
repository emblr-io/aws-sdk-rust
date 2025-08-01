// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request isn't valid. This can occur if your request contains malformed JSON or unsupported characters.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ValidationException {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::string::String,
    /// <p>The reason for the validation exception.</p>
    pub reason: ::std::option::Option<crate::types::ValidationExceptionReason>,
    /// <p>The list of fields that failed to validate.</p>
    pub fields: ::std::option::Option<::std::vec::Vec<crate::types::ValidationExceptionField>>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl ValidationException {
    /// <p>The reason for the validation exception.</p>
    pub fn reason(&self) -> ::std::option::Option<&crate::types::ValidationExceptionReason> {
        self.reason.as_ref()
    }
    /// <p>The list of fields that failed to validate.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.fields.is_none()`.
    pub fn fields(&self) -> &[crate::types::ValidationExceptionField] {
        self.fields.as_deref().unwrap_or_default()
    }
}
impl ValidationException {
    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}
impl ::std::fmt::Display for ValidationException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "ValidationException")?;
        {
            ::std::write!(f, ": {}", &self.message)?;
        }
        Ok(())
    }
}
impl ::std::error::Error for ValidationException {}
impl ::aws_types::request_id::RequestId for crate::types::error::ValidationException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for ValidationException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl ValidationException {
    /// Creates a new builder-style object to manufacture [`ValidationException`](crate::types::error::ValidationException).
    pub fn builder() -> crate::types::error::builders::ValidationExceptionBuilder {
        crate::types::error::builders::ValidationExceptionBuilder::default()
    }
}

/// A builder for [`ValidationException`](crate::types::error::ValidationException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ValidationExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) reason: ::std::option::Option<crate::types::ValidationExceptionReason>,
    pub(crate) fields: ::std::option::Option<::std::vec::Vec<crate::types::ValidationExceptionField>>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl ValidationExceptionBuilder {
    #[allow(missing_docs)] // documentation missing in model
    /// This field is required.
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
    /// <p>The reason for the validation exception.</p>
    pub fn reason(mut self, input: crate::types::ValidationExceptionReason) -> Self {
        self.reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reason for the validation exception.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<crate::types::ValidationExceptionReason>) -> Self {
        self.reason = input;
        self
    }
    /// <p>The reason for the validation exception.</p>
    pub fn get_reason(&self) -> &::std::option::Option<crate::types::ValidationExceptionReason> {
        &self.reason
    }
    /// Appends an item to `fields`.
    ///
    /// To override the contents of this collection use [`set_fields`](Self::set_fields).
    ///
    /// <p>The list of fields that failed to validate.</p>
    pub fn fields(mut self, input: crate::types::ValidationExceptionField) -> Self {
        let mut v = self.fields.unwrap_or_default();
        v.push(input);
        self.fields = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of fields that failed to validate.</p>
    pub fn set_fields(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ValidationExceptionField>>) -> Self {
        self.fields = input;
        self
    }
    /// <p>The list of fields that failed to validate.</p>
    pub fn get_fields(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ValidationExceptionField>> {
        &self.fields
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
    /// Consumes the builder and constructs a [`ValidationException`](crate::types::error::ValidationException).
    /// This method will fail if any of the following fields are not set:
    /// - [`message`](crate::types::error::builders::ValidationExceptionBuilder::message)
    pub fn build(self) -> ::std::result::Result<crate::types::error::ValidationException, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::error::ValidationException {
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building ValidationException",
                )
            })?,
            reason: self.reason,
            fields: self.fields,
            meta: self.meta.unwrap_or_default(),
        })
    }
}
