// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDataRetentionInput {
    /// <p>The name of the stream whose retention period you want to change.</p>
    pub stream_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the stream whose retention period you want to change.</p>
    pub stream_arn: ::std::option::Option<::std::string::String>,
    /// <p>The version of the stream whose retention period you want to change. To get the version, call either the <code>DescribeStream</code> or the <code>ListStreams</code> API.</p>
    pub current_version: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether you want to increase or decrease the retention period.</p>
    pub operation: ::std::option::Option<crate::types::UpdateDataRetentionOperation>,
    /// <p>The number of hours to adjust the current retention by. The value you specify is added to or subtracted from the current value, depending on the <code>operation</code>.</p>
    /// <p>The minimum value for data retention is 0 and the maximum value is 87600 (ten years).</p>
    pub data_retention_change_in_hours: ::std::option::Option<i32>,
}
impl UpdateDataRetentionInput {
    /// <p>The name of the stream whose retention period you want to change.</p>
    pub fn stream_name(&self) -> ::std::option::Option<&str> {
        self.stream_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the stream whose retention period you want to change.</p>
    pub fn stream_arn(&self) -> ::std::option::Option<&str> {
        self.stream_arn.as_deref()
    }
    /// <p>The version of the stream whose retention period you want to change. To get the version, call either the <code>DescribeStream</code> or the <code>ListStreams</code> API.</p>
    pub fn current_version(&self) -> ::std::option::Option<&str> {
        self.current_version.as_deref()
    }
    /// <p>Indicates whether you want to increase or decrease the retention period.</p>
    pub fn operation(&self) -> ::std::option::Option<&crate::types::UpdateDataRetentionOperation> {
        self.operation.as_ref()
    }
    /// <p>The number of hours to adjust the current retention by. The value you specify is added to or subtracted from the current value, depending on the <code>operation</code>.</p>
    /// <p>The minimum value for data retention is 0 and the maximum value is 87600 (ten years).</p>
    pub fn data_retention_change_in_hours(&self) -> ::std::option::Option<i32> {
        self.data_retention_change_in_hours
    }
}
impl UpdateDataRetentionInput {
    /// Creates a new builder-style object to manufacture [`UpdateDataRetentionInput`](crate::operation::update_data_retention::UpdateDataRetentionInput).
    pub fn builder() -> crate::operation::update_data_retention::builders::UpdateDataRetentionInputBuilder {
        crate::operation::update_data_retention::builders::UpdateDataRetentionInputBuilder::default()
    }
}

/// A builder for [`UpdateDataRetentionInput`](crate::operation::update_data_retention::UpdateDataRetentionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDataRetentionInputBuilder {
    pub(crate) stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) stream_arn: ::std::option::Option<::std::string::String>,
    pub(crate) current_version: ::std::option::Option<::std::string::String>,
    pub(crate) operation: ::std::option::Option<crate::types::UpdateDataRetentionOperation>,
    pub(crate) data_retention_change_in_hours: ::std::option::Option<i32>,
}
impl UpdateDataRetentionInputBuilder {
    /// <p>The name of the stream whose retention period you want to change.</p>
    pub fn stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stream whose retention period you want to change.</p>
    pub fn set_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_name = input;
        self
    }
    /// <p>The name of the stream whose retention period you want to change.</p>
    pub fn get_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_name
    }
    /// <p>The Amazon Resource Name (ARN) of the stream whose retention period you want to change.</p>
    pub fn stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the stream whose retention period you want to change.</p>
    pub fn set_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the stream whose retention period you want to change.</p>
    pub fn get_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_arn
    }
    /// <p>The version of the stream whose retention period you want to change. To get the version, call either the <code>DescribeStream</code> or the <code>ListStreams</code> API.</p>
    /// This field is required.
    pub fn current_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.current_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the stream whose retention period you want to change. To get the version, call either the <code>DescribeStream</code> or the <code>ListStreams</code> API.</p>
    pub fn set_current_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.current_version = input;
        self
    }
    /// <p>The version of the stream whose retention period you want to change. To get the version, call either the <code>DescribeStream</code> or the <code>ListStreams</code> API.</p>
    pub fn get_current_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.current_version
    }
    /// <p>Indicates whether you want to increase or decrease the retention period.</p>
    /// This field is required.
    pub fn operation(mut self, input: crate::types::UpdateDataRetentionOperation) -> Self {
        self.operation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether you want to increase or decrease the retention period.</p>
    pub fn set_operation(mut self, input: ::std::option::Option<crate::types::UpdateDataRetentionOperation>) -> Self {
        self.operation = input;
        self
    }
    /// <p>Indicates whether you want to increase or decrease the retention period.</p>
    pub fn get_operation(&self) -> &::std::option::Option<crate::types::UpdateDataRetentionOperation> {
        &self.operation
    }
    /// <p>The number of hours to adjust the current retention by. The value you specify is added to or subtracted from the current value, depending on the <code>operation</code>.</p>
    /// <p>The minimum value for data retention is 0 and the maximum value is 87600 (ten years).</p>
    /// This field is required.
    pub fn data_retention_change_in_hours(mut self, input: i32) -> Self {
        self.data_retention_change_in_hours = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of hours to adjust the current retention by. The value you specify is added to or subtracted from the current value, depending on the <code>operation</code>.</p>
    /// <p>The minimum value for data retention is 0 and the maximum value is 87600 (ten years).</p>
    pub fn set_data_retention_change_in_hours(mut self, input: ::std::option::Option<i32>) -> Self {
        self.data_retention_change_in_hours = input;
        self
    }
    /// <p>The number of hours to adjust the current retention by. The value you specify is added to or subtracted from the current value, depending on the <code>operation</code>.</p>
    /// <p>The minimum value for data retention is 0 and the maximum value is 87600 (ten years).</p>
    pub fn get_data_retention_change_in_hours(&self) -> &::std::option::Option<i32> {
        &self.data_retention_change_in_hours
    }
    /// Consumes the builder and constructs a [`UpdateDataRetentionInput`](crate::operation::update_data_retention::UpdateDataRetentionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_data_retention::UpdateDataRetentionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_data_retention::UpdateDataRetentionInput {
            stream_name: self.stream_name,
            stream_arn: self.stream_arn,
            current_version: self.current_version,
            operation: self.operation,
            data_retention_change_in_hours: self.data_retention_change_in_hours,
        })
    }
}
