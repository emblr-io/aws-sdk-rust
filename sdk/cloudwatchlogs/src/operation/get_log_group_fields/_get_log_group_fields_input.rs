// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLogGroupFieldsInput {
    /// <p>The name of the log group to search.</p><note>
    /// <p>You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both.</p>
    /// </note>
    pub log_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The time to set as the center of the query. If you specify <code>time</code>, the 8 minutes before and 8 minutes after this time are searched. If you omit <code>time</code>, the most recent 15 minutes up to the current time are searched.</p>
    /// <p>The <code>time</code> value is specified as epoch time, which is the number of seconds since <code>January 1, 1970, 00:00:00 UTC</code>.</p>
    pub time: ::std::option::Option<i64>,
    /// <p>Specify either the name or ARN of the log group to view. If the log group is in a source account and you are using a monitoring account, you must specify the ARN.</p><note>
    /// <p>You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both.</p>
    /// </note>
    pub log_group_identifier: ::std::option::Option<::std::string::String>,
}
impl GetLogGroupFieldsInput {
    /// <p>The name of the log group to search.</p><note>
    /// <p>You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both.</p>
    /// </note>
    pub fn log_group_name(&self) -> ::std::option::Option<&str> {
        self.log_group_name.as_deref()
    }
    /// <p>The time to set as the center of the query. If you specify <code>time</code>, the 8 minutes before and 8 minutes after this time are searched. If you omit <code>time</code>, the most recent 15 minutes up to the current time are searched.</p>
    /// <p>The <code>time</code> value is specified as epoch time, which is the number of seconds since <code>January 1, 1970, 00:00:00 UTC</code>.</p>
    pub fn time(&self) -> ::std::option::Option<i64> {
        self.time
    }
    /// <p>Specify either the name or ARN of the log group to view. If the log group is in a source account and you are using a monitoring account, you must specify the ARN.</p><note>
    /// <p>You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both.</p>
    /// </note>
    pub fn log_group_identifier(&self) -> ::std::option::Option<&str> {
        self.log_group_identifier.as_deref()
    }
}
impl GetLogGroupFieldsInput {
    /// Creates a new builder-style object to manufacture [`GetLogGroupFieldsInput`](crate::operation::get_log_group_fields::GetLogGroupFieldsInput).
    pub fn builder() -> crate::operation::get_log_group_fields::builders::GetLogGroupFieldsInputBuilder {
        crate::operation::get_log_group_fields::builders::GetLogGroupFieldsInputBuilder::default()
    }
}

/// A builder for [`GetLogGroupFieldsInput`](crate::operation::get_log_group_fields::GetLogGroupFieldsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLogGroupFieldsInputBuilder {
    pub(crate) log_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) time: ::std::option::Option<i64>,
    pub(crate) log_group_identifier: ::std::option::Option<::std::string::String>,
}
impl GetLogGroupFieldsInputBuilder {
    /// <p>The name of the log group to search.</p><note>
    /// <p>You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both.</p>
    /// </note>
    pub fn log_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the log group to search.</p><note>
    /// <p>You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both.</p>
    /// </note>
    pub fn set_log_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_name = input;
        self
    }
    /// <p>The name of the log group to search.</p><note>
    /// <p>You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both.</p>
    /// </note>
    pub fn get_log_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_name
    }
    /// <p>The time to set as the center of the query. If you specify <code>time</code>, the 8 minutes before and 8 minutes after this time are searched. If you omit <code>time</code>, the most recent 15 minutes up to the current time are searched.</p>
    /// <p>The <code>time</code> value is specified as epoch time, which is the number of seconds since <code>January 1, 1970, 00:00:00 UTC</code>.</p>
    pub fn time(mut self, input: i64) -> Self {
        self.time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time to set as the center of the query. If you specify <code>time</code>, the 8 minutes before and 8 minutes after this time are searched. If you omit <code>time</code>, the most recent 15 minutes up to the current time are searched.</p>
    /// <p>The <code>time</code> value is specified as epoch time, which is the number of seconds since <code>January 1, 1970, 00:00:00 UTC</code>.</p>
    pub fn set_time(mut self, input: ::std::option::Option<i64>) -> Self {
        self.time = input;
        self
    }
    /// <p>The time to set as the center of the query. If you specify <code>time</code>, the 8 minutes before and 8 minutes after this time are searched. If you omit <code>time</code>, the most recent 15 minutes up to the current time are searched.</p>
    /// <p>The <code>time</code> value is specified as epoch time, which is the number of seconds since <code>January 1, 1970, 00:00:00 UTC</code>.</p>
    pub fn get_time(&self) -> &::std::option::Option<i64> {
        &self.time
    }
    /// <p>Specify either the name or ARN of the log group to view. If the log group is in a source account and you are using a monitoring account, you must specify the ARN.</p><note>
    /// <p>You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both.</p>
    /// </note>
    pub fn log_group_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify either the name or ARN of the log group to view. If the log group is in a source account and you are using a monitoring account, you must specify the ARN.</p><note>
    /// <p>You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both.</p>
    /// </note>
    pub fn set_log_group_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_identifier = input;
        self
    }
    /// <p>Specify either the name or ARN of the log group to view. If the log group is in a source account and you are using a monitoring account, you must specify the ARN.</p><note>
    /// <p>You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both.</p>
    /// </note>
    pub fn get_log_group_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_identifier
    }
    /// Consumes the builder and constructs a [`GetLogGroupFieldsInput`](crate::operation::get_log_group_fields::GetLogGroupFieldsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_log_group_fields::GetLogGroupFieldsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_log_group_fields::GetLogGroupFieldsInput {
            log_group_name: self.log_group_name,
            time: self.time,
            log_group_identifier: self.log_group_identifier,
        })
    }
}
