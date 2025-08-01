// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTemplateStepInput {
    /// <p>The ID of the step.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the template.</p>
    pub template_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the step group.</p>
    pub step_group_id: ::std::option::Option<::std::string::String>,
}
impl GetTemplateStepInput {
    /// <p>The ID of the step.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
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
impl GetTemplateStepInput {
    /// Creates a new builder-style object to manufacture [`GetTemplateStepInput`](crate::operation::get_template_step::GetTemplateStepInput).
    pub fn builder() -> crate::operation::get_template_step::builders::GetTemplateStepInputBuilder {
        crate::operation::get_template_step::builders::GetTemplateStepInputBuilder::default()
    }
}

/// A builder for [`GetTemplateStepInput`](crate::operation::get_template_step::GetTemplateStepInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTemplateStepInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) template_id: ::std::option::Option<::std::string::String>,
    pub(crate) step_group_id: ::std::option::Option<::std::string::String>,
}
impl GetTemplateStepInputBuilder {
    /// <p>The ID of the step.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the step.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the step.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
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
    /// Consumes the builder and constructs a [`GetTemplateStepInput`](crate::operation::get_template_step::GetTemplateStepInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_template_step::GetTemplateStepInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_template_step::GetTemplateStepInput {
            id: self.id,
            template_id: self.template_id,
            step_group_id: self.step_group_id,
        })
    }
}
