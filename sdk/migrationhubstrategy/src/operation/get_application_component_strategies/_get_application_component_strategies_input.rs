// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetApplicationComponentStrategiesInput {
    /// <p>The ID of the application component. The ID is unique within an AWS account.</p>
    pub application_component_id: ::std::option::Option<::std::string::String>,
}
impl GetApplicationComponentStrategiesInput {
    /// <p>The ID of the application component. The ID is unique within an AWS account.</p>
    pub fn application_component_id(&self) -> ::std::option::Option<&str> {
        self.application_component_id.as_deref()
    }
}
impl GetApplicationComponentStrategiesInput {
    /// Creates a new builder-style object to manufacture [`GetApplicationComponentStrategiesInput`](crate::operation::get_application_component_strategies::GetApplicationComponentStrategiesInput).
    pub fn builder() -> crate::operation::get_application_component_strategies::builders::GetApplicationComponentStrategiesInputBuilder {
        crate::operation::get_application_component_strategies::builders::GetApplicationComponentStrategiesInputBuilder::default()
    }
}

/// A builder for [`GetApplicationComponentStrategiesInput`](crate::operation::get_application_component_strategies::GetApplicationComponentStrategiesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetApplicationComponentStrategiesInputBuilder {
    pub(crate) application_component_id: ::std::option::Option<::std::string::String>,
}
impl GetApplicationComponentStrategiesInputBuilder {
    /// <p>The ID of the application component. The ID is unique within an AWS account.</p>
    /// This field is required.
    pub fn application_component_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_component_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the application component. The ID is unique within an AWS account.</p>
    pub fn set_application_component_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_component_id = input;
        self
    }
    /// <p>The ID of the application component. The ID is unique within an AWS account.</p>
    pub fn get_application_component_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_component_id
    }
    /// Consumes the builder and constructs a [`GetApplicationComponentStrategiesInput`](crate::operation::get_application_component_strategies::GetApplicationComponentStrategiesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_application_component_strategies::GetApplicationComponentStrategiesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_application_component_strategies::GetApplicationComponentStrategiesInput {
                application_component_id: self.application_component_id,
            },
        )
    }
}
