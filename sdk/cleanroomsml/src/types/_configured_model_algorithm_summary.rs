// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides summary information about a configured model algorithm.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConfiguredModelAlgorithmSummary {
    /// <p>The time at which the configured model algorithm was created.</p>
    pub create_time: ::aws_smithy_types::DateTime,
    /// <p>The most recent time at which the configured model algorithm was updated.</p>
    pub update_time: ::aws_smithy_types::DateTime,
    /// <p>The Amazon Resource Name (ARN) of the configured model algorithm.</p>
    pub configured_model_algorithm_arn: ::std::string::String,
    /// <p>The name of the configured model algorithm.</p>
    pub name: ::std::string::String,
    /// <p>The description of the configured model algorithm.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl ConfiguredModelAlgorithmSummary {
    /// <p>The time at which the configured model algorithm was created.</p>
    pub fn create_time(&self) -> &::aws_smithy_types::DateTime {
        &self.create_time
    }
    /// <p>The most recent time at which the configured model algorithm was updated.</p>
    pub fn update_time(&self) -> &::aws_smithy_types::DateTime {
        &self.update_time
    }
    /// <p>The Amazon Resource Name (ARN) of the configured model algorithm.</p>
    pub fn configured_model_algorithm_arn(&self) -> &str {
        use std::ops::Deref;
        self.configured_model_algorithm_arn.deref()
    }
    /// <p>The name of the configured model algorithm.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The description of the configured model algorithm.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl ConfiguredModelAlgorithmSummary {
    /// Creates a new builder-style object to manufacture [`ConfiguredModelAlgorithmSummary`](crate::types::ConfiguredModelAlgorithmSummary).
    pub fn builder() -> crate::types::builders::ConfiguredModelAlgorithmSummaryBuilder {
        crate::types::builders::ConfiguredModelAlgorithmSummaryBuilder::default()
    }
}

/// A builder for [`ConfiguredModelAlgorithmSummary`](crate::types::ConfiguredModelAlgorithmSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConfiguredModelAlgorithmSummaryBuilder {
    pub(crate) create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) configured_model_algorithm_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl ConfiguredModelAlgorithmSummaryBuilder {
    /// <p>The time at which the configured model algorithm was created.</p>
    /// This field is required.
    pub fn create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the configured model algorithm was created.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>The time at which the configured model algorithm was created.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_time
    }
    /// <p>The most recent time at which the configured model algorithm was updated.</p>
    /// This field is required.
    pub fn update_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.update_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The most recent time at which the configured model algorithm was updated.</p>
    pub fn set_update_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.update_time = input;
        self
    }
    /// <p>The most recent time at which the configured model algorithm was updated.</p>
    pub fn get_update_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.update_time
    }
    /// <p>The Amazon Resource Name (ARN) of the configured model algorithm.</p>
    /// This field is required.
    pub fn configured_model_algorithm_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configured_model_algorithm_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the configured model algorithm.</p>
    pub fn set_configured_model_algorithm_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configured_model_algorithm_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the configured model algorithm.</p>
    pub fn get_configured_model_algorithm_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.configured_model_algorithm_arn
    }
    /// <p>The name of the configured model algorithm.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the configured model algorithm.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the configured model algorithm.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the configured model algorithm.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the configured model algorithm.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the configured model algorithm.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`ConfiguredModelAlgorithmSummary`](crate::types::ConfiguredModelAlgorithmSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`create_time`](crate::types::builders::ConfiguredModelAlgorithmSummaryBuilder::create_time)
    /// - [`update_time`](crate::types::builders::ConfiguredModelAlgorithmSummaryBuilder::update_time)
    /// - [`configured_model_algorithm_arn`](crate::types::builders::ConfiguredModelAlgorithmSummaryBuilder::configured_model_algorithm_arn)
    /// - [`name`](crate::types::builders::ConfiguredModelAlgorithmSummaryBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::ConfiguredModelAlgorithmSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ConfiguredModelAlgorithmSummary {
            create_time: self.create_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "create_time",
                    "create_time was not specified but it is required when building ConfiguredModelAlgorithmSummary",
                )
            })?,
            update_time: self.update_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "update_time",
                    "update_time was not specified but it is required when building ConfiguredModelAlgorithmSummary",
                )
            })?,
            configured_model_algorithm_arn: self.configured_model_algorithm_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "configured_model_algorithm_arn",
                    "configured_model_algorithm_arn was not specified but it is required when building ConfiguredModelAlgorithmSummary",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building ConfiguredModelAlgorithmSummary",
                )
            })?,
            description: self.description,
        })
    }
}
