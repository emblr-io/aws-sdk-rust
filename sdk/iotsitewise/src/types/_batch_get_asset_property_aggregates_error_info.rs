// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the error code and the timestamp for an asset property aggregate entry that is associated with the <a href="https://docs.aws.amazon.com/iot-sitewise/latest/APIReference/API_BatchGetAssetPropertyAggregates.html">BatchGetAssetPropertyAggregates</a> API.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetAssetPropertyAggregatesErrorInfo {
    /// <p>The error code.</p>
    pub error_code: crate::types::BatchGetAssetPropertyAggregatesErrorCode,
    /// <p>The date the error occurred, in Unix epoch time.</p>
    pub error_timestamp: ::aws_smithy_types::DateTime,
}
impl BatchGetAssetPropertyAggregatesErrorInfo {
    /// <p>The error code.</p>
    pub fn error_code(&self) -> &crate::types::BatchGetAssetPropertyAggregatesErrorCode {
        &self.error_code
    }
    /// <p>The date the error occurred, in Unix epoch time.</p>
    pub fn error_timestamp(&self) -> &::aws_smithy_types::DateTime {
        &self.error_timestamp
    }
}
impl BatchGetAssetPropertyAggregatesErrorInfo {
    /// Creates a new builder-style object to manufacture [`BatchGetAssetPropertyAggregatesErrorInfo`](crate::types::BatchGetAssetPropertyAggregatesErrorInfo).
    pub fn builder() -> crate::types::builders::BatchGetAssetPropertyAggregatesErrorInfoBuilder {
        crate::types::builders::BatchGetAssetPropertyAggregatesErrorInfoBuilder::default()
    }
}

/// A builder for [`BatchGetAssetPropertyAggregatesErrorInfo`](crate::types::BatchGetAssetPropertyAggregatesErrorInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetAssetPropertyAggregatesErrorInfoBuilder {
    pub(crate) error_code: ::std::option::Option<crate::types::BatchGetAssetPropertyAggregatesErrorCode>,
    pub(crate) error_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl BatchGetAssetPropertyAggregatesErrorInfoBuilder {
    /// <p>The error code.</p>
    /// This field is required.
    pub fn error_code(mut self, input: crate::types::BatchGetAssetPropertyAggregatesErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The error code.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::BatchGetAssetPropertyAggregatesErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The error code.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::BatchGetAssetPropertyAggregatesErrorCode> {
        &self.error_code
    }
    /// <p>The date the error occurred, in Unix epoch time.</p>
    /// This field is required.
    pub fn error_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.error_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date the error occurred, in Unix epoch time.</p>
    pub fn set_error_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.error_timestamp = input;
        self
    }
    /// <p>The date the error occurred, in Unix epoch time.</p>
    pub fn get_error_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.error_timestamp
    }
    /// Consumes the builder and constructs a [`BatchGetAssetPropertyAggregatesErrorInfo`](crate::types::BatchGetAssetPropertyAggregatesErrorInfo).
    /// This method will fail if any of the following fields are not set:
    /// - [`error_code`](crate::types::builders::BatchGetAssetPropertyAggregatesErrorInfoBuilder::error_code)
    /// - [`error_timestamp`](crate::types::builders::BatchGetAssetPropertyAggregatesErrorInfoBuilder::error_timestamp)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::BatchGetAssetPropertyAggregatesErrorInfo, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BatchGetAssetPropertyAggregatesErrorInfo {
            error_code: self.error_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "error_code",
                    "error_code was not specified but it is required when building BatchGetAssetPropertyAggregatesErrorInfo",
                )
            })?,
            error_timestamp: self.error_timestamp.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "error_timestamp",
                    "error_timestamp was not specified but it is required when building BatchGetAssetPropertyAggregatesErrorInfo",
                )
            })?,
        })
    }
}
