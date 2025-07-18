// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartWorkflowInput {
    /// <p>The ID of the migration workflow.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl StartWorkflowInput {
    /// <p>The ID of the migration workflow.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl StartWorkflowInput {
    /// Creates a new builder-style object to manufacture [`StartWorkflowInput`](crate::operation::start_workflow::StartWorkflowInput).
    pub fn builder() -> crate::operation::start_workflow::builders::StartWorkflowInputBuilder {
        crate::operation::start_workflow::builders::StartWorkflowInputBuilder::default()
    }
}

/// A builder for [`StartWorkflowInput`](crate::operation::start_workflow::StartWorkflowInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartWorkflowInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl StartWorkflowInputBuilder {
    /// <p>The ID of the migration workflow.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the migration workflow.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the migration workflow.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`StartWorkflowInput`](crate::operation::start_workflow::StartWorkflowInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_workflow::StartWorkflowInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_workflow::StartWorkflowInput { id: self.id })
    }
}
