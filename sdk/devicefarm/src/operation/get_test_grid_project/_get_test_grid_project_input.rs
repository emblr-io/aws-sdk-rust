// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTestGridProjectInput {
    /// <p>The ARN of the Selenium testing project, from either <code>CreateTestGridProject</code> or <code>ListTestGridProjects</code>.</p>
    pub project_arn: ::std::option::Option<::std::string::String>,
}
impl GetTestGridProjectInput {
    /// <p>The ARN of the Selenium testing project, from either <code>CreateTestGridProject</code> or <code>ListTestGridProjects</code>.</p>
    pub fn project_arn(&self) -> ::std::option::Option<&str> {
        self.project_arn.as_deref()
    }
}
impl GetTestGridProjectInput {
    /// Creates a new builder-style object to manufacture [`GetTestGridProjectInput`](crate::operation::get_test_grid_project::GetTestGridProjectInput).
    pub fn builder() -> crate::operation::get_test_grid_project::builders::GetTestGridProjectInputBuilder {
        crate::operation::get_test_grid_project::builders::GetTestGridProjectInputBuilder::default()
    }
}

/// A builder for [`GetTestGridProjectInput`](crate::operation::get_test_grid_project::GetTestGridProjectInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTestGridProjectInputBuilder {
    pub(crate) project_arn: ::std::option::Option<::std::string::String>,
}
impl GetTestGridProjectInputBuilder {
    /// <p>The ARN of the Selenium testing project, from either <code>CreateTestGridProject</code> or <code>ListTestGridProjects</code>.</p>
    /// This field is required.
    pub fn project_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the Selenium testing project, from either <code>CreateTestGridProject</code> or <code>ListTestGridProjects</code>.</p>
    pub fn set_project_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project_arn = input;
        self
    }
    /// <p>The ARN of the Selenium testing project, from either <code>CreateTestGridProject</code> or <code>ListTestGridProjects</code>.</p>
    pub fn get_project_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.project_arn
    }
    /// Consumes the builder and constructs a [`GetTestGridProjectInput`](crate::operation::get_test_grid_project::GetTestGridProjectInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_test_grid_project::GetTestGridProjectInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_test_grid_project::GetTestGridProjectInput {
            project_arn: self.project_arn,
        })
    }
}
