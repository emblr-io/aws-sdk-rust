// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the compare data sets step output.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CompareDataSetsStepOutput {
    /// <p>The comparison output location of the compare data sets step output.</p>
    pub comparison_output_location: ::std::string::String,
    /// <p>The comparison status of the compare data sets step output.</p>
    pub comparison_status: crate::types::ComparisonStatusEnum,
}
impl CompareDataSetsStepOutput {
    /// <p>The comparison output location of the compare data sets step output.</p>
    pub fn comparison_output_location(&self) -> &str {
        use std::ops::Deref;
        self.comparison_output_location.deref()
    }
    /// <p>The comparison status of the compare data sets step output.</p>
    pub fn comparison_status(&self) -> &crate::types::ComparisonStatusEnum {
        &self.comparison_status
    }
}
impl CompareDataSetsStepOutput {
    /// Creates a new builder-style object to manufacture [`CompareDataSetsStepOutput`](crate::types::CompareDataSetsStepOutput).
    pub fn builder() -> crate::types::builders::CompareDataSetsStepOutputBuilder {
        crate::types::builders::CompareDataSetsStepOutputBuilder::default()
    }
}

/// A builder for [`CompareDataSetsStepOutput`](crate::types::CompareDataSetsStepOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CompareDataSetsStepOutputBuilder {
    pub(crate) comparison_output_location: ::std::option::Option<::std::string::String>,
    pub(crate) comparison_status: ::std::option::Option<crate::types::ComparisonStatusEnum>,
}
impl CompareDataSetsStepOutputBuilder {
    /// <p>The comparison output location of the compare data sets step output.</p>
    /// This field is required.
    pub fn comparison_output_location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.comparison_output_location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The comparison output location of the compare data sets step output.</p>
    pub fn set_comparison_output_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.comparison_output_location = input;
        self
    }
    /// <p>The comparison output location of the compare data sets step output.</p>
    pub fn get_comparison_output_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.comparison_output_location
    }
    /// <p>The comparison status of the compare data sets step output.</p>
    /// This field is required.
    pub fn comparison_status(mut self, input: crate::types::ComparisonStatusEnum) -> Self {
        self.comparison_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The comparison status of the compare data sets step output.</p>
    pub fn set_comparison_status(mut self, input: ::std::option::Option<crate::types::ComparisonStatusEnum>) -> Self {
        self.comparison_status = input;
        self
    }
    /// <p>The comparison status of the compare data sets step output.</p>
    pub fn get_comparison_status(&self) -> &::std::option::Option<crate::types::ComparisonStatusEnum> {
        &self.comparison_status
    }
    /// Consumes the builder and constructs a [`CompareDataSetsStepOutput`](crate::types::CompareDataSetsStepOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`comparison_output_location`](crate::types::builders::CompareDataSetsStepOutputBuilder::comparison_output_location)
    /// - [`comparison_status`](crate::types::builders::CompareDataSetsStepOutputBuilder::comparison_status)
    pub fn build(self) -> ::std::result::Result<crate::types::CompareDataSetsStepOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CompareDataSetsStepOutput {
            comparison_output_location: self.comparison_output_location.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "comparison_output_location",
                    "comparison_output_location was not specified but it is required when building CompareDataSetsStepOutput",
                )
            })?,
            comparison_status: self.comparison_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "comparison_status",
                    "comparison_status was not specified but it is required when building CompareDataSetsStepOutput",
                )
            })?,
        })
    }
}
