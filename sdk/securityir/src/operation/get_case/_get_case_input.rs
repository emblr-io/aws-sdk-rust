// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCaseInput {
    /// <p>Required element for GetCase to identify the requested case ID.</p>
    pub case_id: ::std::option::Option<::std::string::String>,
}
impl GetCaseInput {
    /// <p>Required element for GetCase to identify the requested case ID.</p>
    pub fn case_id(&self) -> ::std::option::Option<&str> {
        self.case_id.as_deref()
    }
}
impl GetCaseInput {
    /// Creates a new builder-style object to manufacture [`GetCaseInput`](crate::operation::get_case::GetCaseInput).
    pub fn builder() -> crate::operation::get_case::builders::GetCaseInputBuilder {
        crate::operation::get_case::builders::GetCaseInputBuilder::default()
    }
}

/// A builder for [`GetCaseInput`](crate::operation::get_case::GetCaseInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCaseInputBuilder {
    pub(crate) case_id: ::std::option::Option<::std::string::String>,
}
impl GetCaseInputBuilder {
    /// <p>Required element for GetCase to identify the requested case ID.</p>
    /// This field is required.
    pub fn case_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.case_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Required element for GetCase to identify the requested case ID.</p>
    pub fn set_case_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.case_id = input;
        self
    }
    /// <p>Required element for GetCase to identify the requested case ID.</p>
    pub fn get_case_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.case_id
    }
    /// Consumes the builder and constructs a [`GetCaseInput`](crate::operation::get_case::GetCaseInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_case::GetCaseInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_case::GetCaseInput { case_id: self.case_id })
    }
}
