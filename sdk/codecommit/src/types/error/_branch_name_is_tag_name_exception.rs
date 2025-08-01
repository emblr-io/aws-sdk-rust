// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The specified branch name is not valid because it is a tag name. Enter the name of a branch in the repository. For a list of valid branch names, use <code>ListBranches</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BranchNameIsTagNameException {
    /// <p>Any message associated with the exception.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl BranchNameIsTagNameException {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for BranchNameIsTagNameException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "BranchNameIsTagNameException")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for BranchNameIsTagNameException {}
impl ::aws_types::request_id::RequestId for crate::types::error::BranchNameIsTagNameException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for BranchNameIsTagNameException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl BranchNameIsTagNameException {
    /// Creates a new builder-style object to manufacture [`BranchNameIsTagNameException`](crate::types::error::BranchNameIsTagNameException).
    pub fn builder() -> crate::types::error::builders::BranchNameIsTagNameExceptionBuilder {
        crate::types::error::builders::BranchNameIsTagNameExceptionBuilder::default()
    }
}

/// A builder for [`BranchNameIsTagNameException`](crate::types::error::BranchNameIsTagNameException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BranchNameIsTagNameExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl BranchNameIsTagNameExceptionBuilder {
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
    /// Consumes the builder and constructs a [`BranchNameIsTagNameException`](crate::types::error::BranchNameIsTagNameException).
    pub fn build(self) -> crate::types::error::BranchNameIsTagNameException {
        crate::types::error::BranchNameIsTagNameException {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
