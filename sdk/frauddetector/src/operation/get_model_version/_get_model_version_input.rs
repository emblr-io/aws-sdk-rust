// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetModelVersionInput {
    /// <p>The model ID.</p>
    pub model_id: ::std::option::Option<::std::string::String>,
    /// <p>The model type.</p>
    pub model_type: ::std::option::Option<crate::types::ModelTypeEnum>,
    /// <p>The model version number.</p>
    pub model_version_number: ::std::option::Option<::std::string::String>,
}
impl GetModelVersionInput {
    /// <p>The model ID.</p>
    pub fn model_id(&self) -> ::std::option::Option<&str> {
        self.model_id.as_deref()
    }
    /// <p>The model type.</p>
    pub fn model_type(&self) -> ::std::option::Option<&crate::types::ModelTypeEnum> {
        self.model_type.as_ref()
    }
    /// <p>The model version number.</p>
    pub fn model_version_number(&self) -> ::std::option::Option<&str> {
        self.model_version_number.as_deref()
    }
}
impl GetModelVersionInput {
    /// Creates a new builder-style object to manufacture [`GetModelVersionInput`](crate::operation::get_model_version::GetModelVersionInput).
    pub fn builder() -> crate::operation::get_model_version::builders::GetModelVersionInputBuilder {
        crate::operation::get_model_version::builders::GetModelVersionInputBuilder::default()
    }
}

/// A builder for [`GetModelVersionInput`](crate::operation::get_model_version::GetModelVersionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetModelVersionInputBuilder {
    pub(crate) model_id: ::std::option::Option<::std::string::String>,
    pub(crate) model_type: ::std::option::Option<crate::types::ModelTypeEnum>,
    pub(crate) model_version_number: ::std::option::Option<::std::string::String>,
}
impl GetModelVersionInputBuilder {
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
    /// <p>The model type.</p>
    /// This field is required.
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
    /// <p>The model version number.</p>
    /// This field is required.
    pub fn model_version_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_version_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The model version number.</p>
    pub fn set_model_version_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_version_number = input;
        self
    }
    /// <p>The model version number.</p>
    pub fn get_model_version_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_version_number
    }
    /// Consumes the builder and constructs a [`GetModelVersionInput`](crate::operation::get_model_version::GetModelVersionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_model_version::GetModelVersionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_model_version::GetModelVersionInput {
            model_id: self.model_id,
            model_type: self.model_type,
            model_version_number: self.model_version_number,
        })
    }
}
