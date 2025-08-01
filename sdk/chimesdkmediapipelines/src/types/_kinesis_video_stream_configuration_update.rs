// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The updated Kinesis video stream configuration object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct KinesisVideoStreamConfigurationUpdate {
    /// <p>The updated time that data is retained.</p>
    pub data_retention_in_hours: ::std::option::Option<i32>,
}
impl KinesisVideoStreamConfigurationUpdate {
    /// <p>The updated time that data is retained.</p>
    pub fn data_retention_in_hours(&self) -> ::std::option::Option<i32> {
        self.data_retention_in_hours
    }
}
impl KinesisVideoStreamConfigurationUpdate {
    /// Creates a new builder-style object to manufacture [`KinesisVideoStreamConfigurationUpdate`](crate::types::KinesisVideoStreamConfigurationUpdate).
    pub fn builder() -> crate::types::builders::KinesisVideoStreamConfigurationUpdateBuilder {
        crate::types::builders::KinesisVideoStreamConfigurationUpdateBuilder::default()
    }
}

/// A builder for [`KinesisVideoStreamConfigurationUpdate`](crate::types::KinesisVideoStreamConfigurationUpdate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct KinesisVideoStreamConfigurationUpdateBuilder {
    pub(crate) data_retention_in_hours: ::std::option::Option<i32>,
}
impl KinesisVideoStreamConfigurationUpdateBuilder {
    /// <p>The updated time that data is retained.</p>
    pub fn data_retention_in_hours(mut self, input: i32) -> Self {
        self.data_retention_in_hours = ::std::option::Option::Some(input);
        self
    }
    /// <p>The updated time that data is retained.</p>
    pub fn set_data_retention_in_hours(mut self, input: ::std::option::Option<i32>) -> Self {
        self.data_retention_in_hours = input;
        self
    }
    /// <p>The updated time that data is retained.</p>
    pub fn get_data_retention_in_hours(&self) -> &::std::option::Option<i32> {
        &self.data_retention_in_hours
    }
    /// Consumes the builder and constructs a [`KinesisVideoStreamConfigurationUpdate`](crate::types::KinesisVideoStreamConfigurationUpdate).
    pub fn build(self) -> crate::types::KinesisVideoStreamConfigurationUpdate {
        crate::types::KinesisVideoStreamConfigurationUpdate {
            data_retention_in_hours: self.data_retention_in_hours,
        }
    }
}
