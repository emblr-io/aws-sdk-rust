// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTemplateStepsInput {
    /// <p>The maximum number of results that can be returned.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The pagination token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the template.</p>
    pub template_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the step group.</p>
    pub step_group_id: ::std::option::Option<::std::string::String>,
}
impl ListTemplateStepsInput {
    /// <p>The maximum number of results that can be returned.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The pagination token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The ID of the template.</p>
    pub fn template_id(&self) -> ::std::option::Option<&str> {
        self.template_id.as_deref()
    }
    /// <p>The ID of the step group.</p>
    pub fn step_group_id(&self) -> ::std::option::Option<&str> {
        self.step_group_id.as_deref()
    }
}
impl ListTemplateStepsInput {
    /// Creates a new builder-style object to manufacture [`ListTemplateStepsInput`](crate::operation::list_template_steps::ListTemplateStepsInput).
    pub fn builder() -> crate::operation::list_template_steps::builders::ListTemplateStepsInputBuilder {
        crate::operation::list_template_steps::builders::ListTemplateStepsInputBuilder::default()
    }
}

/// A builder for [`ListTemplateStepsInput`](crate::operation::list_template_steps::ListTemplateStepsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTemplateStepsInputBuilder {
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) template_id: ::std::option::Option<::std::string::String>,
    pub(crate) step_group_id: ::std::option::Option<::std::string::String>,
}
impl ListTemplateStepsInputBuilder {
    /// <p>The maximum number of results that can be returned.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results that can be returned.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results that can be returned.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The pagination token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The ID of the template.</p>
    /// This field is required.
    pub fn template_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the template.</p>
    pub fn set_template_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_id = input;
        self
    }
    /// <p>The ID of the template.</p>
    pub fn get_template_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_id
    }
    /// <p>The ID of the step group.</p>
    /// This field is required.
    pub fn step_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.step_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the step group.</p>
    pub fn set_step_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.step_group_id = input;
        self
    }
    /// <p>The ID of the step group.</p>
    pub fn get_step_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.step_group_id
    }
    /// Consumes the builder and constructs a [`ListTemplateStepsInput`](crate::operation::list_template_steps::ListTemplateStepsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_template_steps::ListTemplateStepsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_template_steps::ListTemplateStepsInput {
            max_results: self.max_results,
            next_token: self.next_token,
            template_id: self.template_id,
            step_group_id: self.step_group_id,
        })
    }
}
