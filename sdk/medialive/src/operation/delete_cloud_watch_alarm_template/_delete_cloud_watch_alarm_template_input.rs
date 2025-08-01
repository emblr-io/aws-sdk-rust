// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for DeleteCloudWatchAlarmTemplateRequest
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteCloudWatchAlarmTemplateInput {
    /// A cloudwatch alarm template's identifier. Can be either be its id or current name.
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteCloudWatchAlarmTemplateInput {
    /// A cloudwatch alarm template's identifier. Can be either be its id or current name.
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl DeleteCloudWatchAlarmTemplateInput {
    /// Creates a new builder-style object to manufacture [`DeleteCloudWatchAlarmTemplateInput`](crate::operation::delete_cloud_watch_alarm_template::DeleteCloudWatchAlarmTemplateInput).
    pub fn builder() -> crate::operation::delete_cloud_watch_alarm_template::builders::DeleteCloudWatchAlarmTemplateInputBuilder {
        crate::operation::delete_cloud_watch_alarm_template::builders::DeleteCloudWatchAlarmTemplateInputBuilder::default()
    }
}

/// A builder for [`DeleteCloudWatchAlarmTemplateInput`](crate::operation::delete_cloud_watch_alarm_template::DeleteCloudWatchAlarmTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteCloudWatchAlarmTemplateInputBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteCloudWatchAlarmTemplateInputBuilder {
    /// A cloudwatch alarm template's identifier. Can be either be its id or current name.
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// A cloudwatch alarm template's identifier. Can be either be its id or current name.
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// A cloudwatch alarm template's identifier. Can be either be its id or current name.
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`DeleteCloudWatchAlarmTemplateInput`](crate::operation::delete_cloud_watch_alarm_template::DeleteCloudWatchAlarmTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_cloud_watch_alarm_template::DeleteCloudWatchAlarmTemplateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_cloud_watch_alarm_template::DeleteCloudWatchAlarmTemplateInput {
            identifier: self.identifier,
        })
    }
}
