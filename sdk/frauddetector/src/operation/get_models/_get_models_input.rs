// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetModelsInput {
    /// <p>The model ID.</p>
    pub model_id: ::std::option::Option<::std::string::String>,
    /// <p>The model type.</p>
    pub model_type: ::std::option::Option<crate::types::ModelTypeEnum>,
    /// <p>The next token for the subsequent request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of objects to return for the request.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl GetModelsInput {
    /// <p>The model ID.</p>
    pub fn model_id(&self) -> ::std::option::Option<&str> {
        self.model_id.as_deref()
    }
    /// <p>The model type.</p>
    pub fn model_type(&self) -> ::std::option::Option<&crate::types::ModelTypeEnum> {
        self.model_type.as_ref()
    }
    /// <p>The next token for the subsequent request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of objects to return for the request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl GetModelsInput {
    /// Creates a new builder-style object to manufacture [`GetModelsInput`](crate::operation::get_models::GetModelsInput).
    pub fn builder() -> crate::operation::get_models::builders::GetModelsInputBuilder {
        crate::operation::get_models::builders::GetModelsInputBuilder::default()
    }
}

/// A builder for [`GetModelsInput`](crate::operation::get_models::GetModelsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetModelsInputBuilder {
    pub(crate) model_id: ::std::option::Option<::std::string::String>,
    pub(crate) model_type: ::std::option::Option<crate::types::ModelTypeEnum>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl GetModelsInputBuilder {
    /// <p>The model ID.</p>
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
    /// <p>The model type.</p>
    pub fn model_type(mut self, input: crate::types::ModelTypeEnum) -> Self {
        self.model_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The model type.</p>
    pub fn set_model_type(mut self, input: ::std::option::Option<crate::types::ModelTypeEnum>) -> Self {
        self.model_type = input;
        self
    }
    /// <p>The model type.</p>
    pub fn get_model_type(&self) -> &::std::option::Option<crate::types::ModelTypeEnum> {
        &self.model_type
    }
    /// <p>The next token for the subsequent request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next token for the subsequent request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The next token for the subsequent request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of objects to return for the request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of objects to return for the request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of objects to return for the request.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`GetModelsInput`](crate::operation::get_models::GetModelsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_models::GetModelsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_models::GetModelsInput {
            model_id: self.model_id,
            model_type: self.model_type,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
