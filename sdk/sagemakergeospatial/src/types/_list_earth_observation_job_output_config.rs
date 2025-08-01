// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object containing information about the output file.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEarthObservationJobOutputConfig {
    /// <p>The Amazon Resource Name (ARN) of the list of the Earth Observation jobs.</p>
    pub arn: ::std::string::String,
    /// <p>The names of the Earth Observation jobs in the list.</p>
    pub name: ::std::string::String,
    /// <p>The creation time.</p>
    pub creation_time: ::aws_smithy_types::DateTime,
    /// <p>The duration of the session, in seconds.</p>
    pub duration_in_seconds: i32,
    /// <p>The status of the list of the Earth Observation jobs.</p>
    pub status: crate::types::EarthObservationJobStatus,
    /// <p>The operation type for an Earth Observation job.</p>
    pub operation_type: ::std::string::String,
    /// <p>Each tag consists of a key and a value.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ListEarthObservationJobOutputConfig {
    /// <p>The Amazon Resource Name (ARN) of the list of the Earth Observation jobs.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The names of the Earth Observation jobs in the list.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The creation time.</p>
    pub fn creation_time(&self) -> &::aws_smithy_types::DateTime {
        &self.creation_time
    }
    /// <p>The duration of the session, in seconds.</p>
    pub fn duration_in_seconds(&self) -> i32 {
        self.duration_in_seconds
    }
    /// <p>The status of the list of the Earth Observation jobs.</p>
    pub fn status(&self) -> &crate::types::EarthObservationJobStatus {
        &self.status
    }
    /// <p>The operation type for an Earth Observation job.</p>
    pub fn operation_type(&self) -> &str {
        use std::ops::Deref;
        self.operation_type.deref()
    }
    /// <p>Each tag consists of a key and a value.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ListEarthObservationJobOutputConfig {
    /// Creates a new builder-style object to manufacture [`ListEarthObservationJobOutputConfig`](crate::types::ListEarthObservationJobOutputConfig).
    pub fn builder() -> crate::types::builders::ListEarthObservationJobOutputConfigBuilder {
        crate::types::builders::ListEarthObservationJobOutputConfigBuilder::default()
    }
}

/// A builder for [`ListEarthObservationJobOutputConfig`](crate::types::ListEarthObservationJobOutputConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEarthObservationJobOutputConfigBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) duration_in_seconds: ::std::option::Option<i32>,
    pub(crate) status: ::std::option::Option<crate::types::EarthObservationJobStatus>,
    pub(crate) operation_type: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ListEarthObservationJobOutputConfigBuilder {
    /// <p>The Amazon Resource Name (ARN) of the list of the Earth Observation jobs.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the list of the Earth Observation jobs.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the list of the Earth Observation jobs.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The names of the Earth Observation jobs in the list.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The names of the Earth Observation jobs in the list.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The names of the Earth Observation jobs in the list.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The creation time.</p>
    /// This field is required.
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The creation time.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The creation time.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The duration of the session, in seconds.</p>
    /// This field is required.
    pub fn duration_in_seconds(mut self, input: i32) -> Self {
        self.duration_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The duration of the session, in seconds.</p>
    pub fn set_duration_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.duration_in_seconds = input;
        self
    }
    /// <p>The duration of the session, in seconds.</p>
    pub fn get_duration_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.duration_in_seconds
    }
    /// <p>The status of the list of the Earth Observation jobs.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::EarthObservationJobStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the list of the Earth Observation jobs.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::EarthObservationJobStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the list of the Earth Observation jobs.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::EarthObservationJobStatus> {
        &self.status
    }
    /// <p>The operation type for an Earth Observation job.</p>
    /// This field is required.
    pub fn operation_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The operation type for an Earth Observation job.</p>
    pub fn set_operation_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation_type = input;
        self
    }
    /// <p>The operation type for an Earth Observation job.</p>
    pub fn get_operation_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation_type
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Each tag consists of a key and a value.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Each tag consists of a key and a value.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Each tag consists of a key and a value.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`ListEarthObservationJobOutputConfig`](crate::types::ListEarthObservationJobOutputConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::ListEarthObservationJobOutputConfigBuilder::arn)
    /// - [`name`](crate::types::builders::ListEarthObservationJobOutputConfigBuilder::name)
    /// - [`creation_time`](crate::types::builders::ListEarthObservationJobOutputConfigBuilder::creation_time)
    /// - [`duration_in_seconds`](crate::types::builders::ListEarthObservationJobOutputConfigBuilder::duration_in_seconds)
    /// - [`status`](crate::types::builders::ListEarthObservationJobOutputConfigBuilder::status)
    /// - [`operation_type`](crate::types::builders::ListEarthObservationJobOutputConfigBuilder::operation_type)
    pub fn build(self) -> ::std::result::Result<crate::types::ListEarthObservationJobOutputConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ListEarthObservationJobOutputConfig {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building ListEarthObservationJobOutputConfig",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building ListEarthObservationJobOutputConfig",
                )
            })?,
            creation_time: self.creation_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "creation_time",
                    "creation_time was not specified but it is required when building ListEarthObservationJobOutputConfig",
                )
            })?,
            duration_in_seconds: self.duration_in_seconds.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "duration_in_seconds",
                    "duration_in_seconds was not specified but it is required when building ListEarthObservationJobOutputConfig",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building ListEarthObservationJobOutputConfig",
                )
            })?,
            operation_type: self.operation_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "operation_type",
                    "operation_type was not specified but it is required when building ListEarthObservationJobOutputConfig",
                )
            })?,
            tags: self.tags,
        })
    }
}
