// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetModelTemplateInput {
    /// <p>The API identifier.</p>
    pub api_id: ::std::option::Option<::std::string::String>,
    /// <p>The model ID.</p>
    pub model_id: ::std::option::Option<::std::string::String>,
}
impl GetModelTemplateInput {
    /// <p>The API identifier.</p>
    pub fn api_id(&self) -> ::std::option::Option<&str> {
        self.api_id.as_deref()
    }
    /// <p>The model ID.</p>
    pub fn model_id(&self) -> ::std::option::Option<&str> {
        self.model_id.as_deref()
    }
}
impl GetModelTemplateInput {
    /// Creates a new builder-style object to manufacture [`GetModelTemplateInput`](crate::operation::get_model_template::GetModelTemplateInput).
    pub fn builder() -> crate::operation::get_model_template::builders::GetModelTemplateInputBuilder {
        crate::operation::get_model_template::builders::GetModelTemplateInputBuilder::default()
    }
}

/// A builder for [`GetModelTemplateInput`](crate::operation::get_model_template::GetModelTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetModelTemplateInputBuilder {
    pub(crate) api_id: ::std::option::Option<::std::string::String>,
    pub(crate) model_id: ::std::option::Option<::std::string::String>,
}
impl GetModelTemplateInputBuilder {
    /// <p>The API identifier.</p>
    /// This field is required.
    pub fn api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The API identifier.</p>
    pub fn set_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_id = input;
        self
    }
    /// <p>The API identifier.</p>
    pub fn get_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_id
    }
    /// <p>The model ID.</p>
    /// This field is required.
    pub fn model_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The model ID.</p>
    pub fn set_model_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_id = input;
        self
    }
    /// <p>The model ID.</p>
    pub fn get_model_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_id
    }
    /// Consumes the builder and constructs a [`GetModelTemplateInput`](crate::operation::get_model_template::GetModelTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_model_template::GetModelTemplateInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_model_template::GetModelTemplateInput {
            api_id: self.api_id,
            model_id: self.model_id,
        })
    }
}
