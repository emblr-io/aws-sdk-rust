// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The control entity attributes that uniquely identify an existing control to be added to a framework in Audit Manager.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAssessmentFrameworkControl {
    /// <p>The unique identifier of the control.</p>
    pub id: ::std::string::String,
}
impl CreateAssessmentFrameworkControl {
    /// <p>The unique identifier of the control.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
}
impl CreateAssessmentFrameworkControl {
    /// Creates a new builder-style object to manufacture [`CreateAssessmentFrameworkControl`](crate::types::CreateAssessmentFrameworkControl).
    pub fn builder() -> crate::types::builders::CreateAssessmentFrameworkControlBuilder {
        crate::types::builders::CreateAssessmentFrameworkControlBuilder::default()
    }
}

/// A builder for [`CreateAssessmentFrameworkControl`](crate::types::CreateAssessmentFrameworkControl).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAssessmentFrameworkControlBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl CreateAssessmentFrameworkControlBuilder {
    /// <p>The unique identifier of the control.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the control.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier of the control.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`CreateAssessmentFrameworkControl`](crate::types::CreateAssessmentFrameworkControl).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::CreateAssessmentFrameworkControlBuilder::id)
    pub fn build(self) -> ::std::result::Result<crate::types::CreateAssessmentFrameworkControl, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CreateAssessmentFrameworkControl {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building CreateAssessmentFrameworkControl",
                )
            })?,
        })
    }
}
