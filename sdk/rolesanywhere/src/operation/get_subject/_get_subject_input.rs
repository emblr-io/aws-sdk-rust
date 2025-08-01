// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSubjectInput {
    /// <p>The unique identifier of the subject.</p>
    pub subject_id: ::std::option::Option<::std::string::String>,
}
impl GetSubjectInput {
    /// <p>The unique identifier of the subject.</p>
    pub fn subject_id(&self) -> ::std::option::Option<&str> {
        self.subject_id.as_deref()
    }
}
impl GetSubjectInput {
    /// Creates a new builder-style object to manufacture [`GetSubjectInput`](crate::operation::get_subject::GetSubjectInput).
    pub fn builder() -> crate::operation::get_subject::builders::GetSubjectInputBuilder {
        crate::operation::get_subject::builders::GetSubjectInputBuilder::default()
    }
}

/// A builder for [`GetSubjectInput`](crate::operation::get_subject::GetSubjectInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSubjectInputBuilder {
    pub(crate) subject_id: ::std::option::Option<::std::string::String>,
}
impl GetSubjectInputBuilder {
    /// <p>The unique identifier of the subject.</p>
    /// This field is required.
    pub fn subject_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subject_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the subject.</p>
    pub fn set_subject_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subject_id = input;
        self
    }
    /// <p>The unique identifier of the subject.</p>
    pub fn get_subject_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subject_id
    }
    /// Consumes the builder and constructs a [`GetSubjectInput`](crate::operation::get_subject::GetSubjectInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_subject::GetSubjectInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_subject::GetSubjectInput { subject_id: self.subject_id })
    }
}
