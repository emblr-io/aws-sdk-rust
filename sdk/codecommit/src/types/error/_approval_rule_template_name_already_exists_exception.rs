// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>You cannot create an approval rule template with that name because a template with that name already exists in this Amazon Web Services Region for your Amazon Web Services account. Approval rule template names must be unique.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ApprovalRuleTemplateNameAlreadyExistsException {
    /// <p>Any message associated with the exception.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl ApprovalRuleTemplateNameAlreadyExistsException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for ApprovalRuleTemplateNameAlreadyExistsException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "ApprovalRuleTemplateNameAlreadyExistsException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for ApprovalRuleTemplateNameAlreadyExistsException {}
impl ::aws_types::request_id::RequestId for crate::types::error::ApprovalRuleTemplateNameAlreadyExistsException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for ApprovalRuleTemplateNameAlreadyExistsException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl ApprovalRuleTemplateNameAlreadyExistsException {
    /// Creates a new builder-style object to manufacture [`ApprovalRuleTemplateNameAlreadyExistsException`](crate::types::error::ApprovalRuleTemplateNameAlreadyExistsException).
    pub fn builder() -> crate::types::error::builders::ApprovalRuleTemplateNameAlreadyExistsExceptionBuilder {
        crate::types::error::builders::ApprovalRuleTemplateNameAlreadyExistsExceptionBuilder::default()
    }
}

/// A builder for [`ApprovalRuleTemplateNameAlreadyExistsException`](crate::types::error::ApprovalRuleTemplateNameAlreadyExistsException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ApprovalRuleTemplateNameAlreadyExistsExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl ApprovalRuleTemplateNameAlreadyExistsExceptionBuilder {
    /// <p>Any message associated with the exception.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Any message associated with the exception.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>Any message associated with the exception.</p>
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
    /// Consumes the builder and constructs a [`ApprovalRuleTemplateNameAlreadyExistsException`](crate::types::error::ApprovalRuleTemplateNameAlreadyExistsException).
    pub fn build(self) -> crate::types::error::ApprovalRuleTemplateNameAlreadyExistsException {
        crate::types::error::ApprovalRuleTemplateNameAlreadyExistsException {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
