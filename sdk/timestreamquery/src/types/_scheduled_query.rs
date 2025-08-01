// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Scheduled Query</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScheduledQuery {
    /// <p>The Amazon Resource Name.</p>
    pub arn: ::std::string::String,
    /// <p>The name of the scheduled query.</p>
    pub name: ::std::string::String,
    /// <p>The creation time of the scheduled query.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>State of scheduled query.</p>
    pub state: crate::types::ScheduledQueryState,
    /// <p>The last time the scheduled query was run.</p>
    pub previous_invocation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The next time the scheduled query is to be run.</p>
    pub next_invocation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Configuration for scheduled query error reporting.</p>
    pub error_report_configuration: ::std::option::Option<crate::types::ErrorReportConfiguration>,
    /// <p>Target data source where final scheduled query result will be written.</p>
    pub target_destination: ::std::option::Option<crate::types::TargetDestination>,
    /// <p>Status of the last scheduled query run.</p>
    pub last_run_status: ::std::option::Option<crate::types::ScheduledQueryRunStatus>,
}
impl ScheduledQuery {
    /// <p>The Amazon Resource Name.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The name of the scheduled query.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The creation time of the scheduled query.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>State of scheduled query.</p>
    pub fn state(&self) -> &crate::types::ScheduledQueryState {
        &self.state
    }
    /// <p>The last time the scheduled query was run.</p>
    pub fn previous_invocation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.previous_invocation_time.as_ref()
    }
    /// <p>The next time the scheduled query is to be run.</p>
    pub fn next_invocation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.next_invocation_time.as_ref()
    }
    /// <p>Configuration for scheduled query error reporting.</p>
    pub fn error_report_configuration(&self) -> ::std::option::Option<&crate::types::ErrorReportConfiguration> {
        self.error_report_configuration.as_ref()
    }
    /// <p>Target data source where final scheduled query result will be written.</p>
    pub fn target_destination(&self) -> ::std::option::Option<&crate::types::TargetDestination> {
        self.target_destination.as_ref()
    }
    /// <p>Status of the last scheduled query run.</p>
    pub fn last_run_status(&self) -> ::std::option::Option<&crate::types::ScheduledQueryRunStatus> {
        self.last_run_status.as_ref()
    }
}
impl ScheduledQuery {
    /// Creates a new builder-style object to manufacture [`ScheduledQuery`](crate::types::ScheduledQuery).
    pub fn builder() -> crate::types::builders::ScheduledQueryBuilder {
        crate::types::builders::ScheduledQueryBuilder::default()
    }
}

/// A builder for [`ScheduledQuery`](crate::types::ScheduledQuery).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScheduledQueryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) state: ::std::option::Option<crate::types::ScheduledQueryState>,
    pub(crate) previous_invocation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) next_invocation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) error_report_configuration: ::std::option::Option<crate::types::ErrorReportConfiguration>,
    pub(crate) target_destination: ::std::option::Option<crate::types::TargetDestination>,
    pub(crate) last_run_status: ::std::option::Option<crate::types::ScheduledQueryRunStatus>,
}
impl ScheduledQueryBuilder {
    /// <p>The Amazon Resource Name.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the scheduled query.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the scheduled query.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the scheduled query.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The creation time of the scheduled query.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The creation time of the scheduled query.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The creation time of the scheduled query.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>State of scheduled query.</p>
    /// This field is required.
    pub fn state(mut self, input: crate::types::ScheduledQueryState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>State of scheduled query.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::ScheduledQueryState>) -> Self {
        self.state = input;
        self
    }
    /// <p>State of scheduled query.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::ScheduledQueryState> {
        &self.state
    }
    /// <p>The last time the scheduled query was run.</p>
    pub fn previous_invocation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.previous_invocation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time the scheduled query was run.</p>
    pub fn set_previous_invocation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.previous_invocation_time = input;
        self
    }
    /// <p>The last time the scheduled query was run.</p>
    pub fn get_previous_invocation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.previous_invocation_time
    }
    /// <p>The next time the scheduled query is to be run.</p>
    pub fn next_invocation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.next_invocation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The next time the scheduled query is to be run.</p>
    pub fn set_next_invocation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.next_invocation_time = input;
        self
    }
    /// <p>The next time the scheduled query is to be run.</p>
    pub fn get_next_invocation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.next_invocation_time
    }
    /// <p>Configuration for scheduled query error reporting.</p>
    pub fn error_report_configuration(mut self, input: crate::types::ErrorReportConfiguration) -> Self {
        self.error_report_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration for scheduled query error reporting.</p>
    pub fn set_error_report_configuration(mut self, input: ::std::option::Option<crate::types::ErrorReportConfiguration>) -> Self {
        self.error_report_configuration = input;
        self
    }
    /// <p>Configuration for scheduled query error reporting.</p>
    pub fn get_error_report_configuration(&self) -> &::std::option::Option<crate::types::ErrorReportConfiguration> {
        &self.error_report_configuration
    }
    /// <p>Target data source where final scheduled query result will be written.</p>
    pub fn target_destination(mut self, input: crate::types::TargetDestination) -> Self {
        self.target_destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>Target data source where final scheduled query result will be written.</p>
    pub fn set_target_destination(mut self, input: ::std::option::Option<crate::types::TargetDestination>) -> Self {
        self.target_destination = input;
        self
    }
    /// <p>Target data source where final scheduled query result will be written.</p>
    pub fn get_target_destination(&self) -> &::std::option::Option<crate::types::TargetDestination> {
        &self.target_destination
    }
    /// <p>Status of the last scheduled query run.</p>
    pub fn last_run_status(mut self, input: crate::types::ScheduledQueryRunStatus) -> Self {
        self.last_run_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status of the last scheduled query run.</p>
    pub fn set_last_run_status(mut self, input: ::std::option::Option<crate::types::ScheduledQueryRunStatus>) -> Self {
        self.last_run_status = input;
        self
    }
    /// <p>Status of the last scheduled query run.</p>
    pub fn get_last_run_status(&self) -> &::std::option::Option<crate::types::ScheduledQueryRunStatus> {
        &self.last_run_status
    }
    /// Consumes the builder and constructs a [`ScheduledQuery`](crate::types::ScheduledQuery).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::ScheduledQueryBuilder::arn)
    /// - [`name`](crate::types::builders::ScheduledQueryBuilder::name)
    /// - [`state`](crate::types::builders::ScheduledQueryBuilder::state)
    pub fn build(self) -> ::std::result::Result<crate::types::ScheduledQuery, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ScheduledQuery {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building ScheduledQuery",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building ScheduledQuery",
                )
            })?,
            creation_time: self.creation_time,
            state: self.state.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "state",
                    "state was not specified but it is required when building ScheduledQuery",
                )
            })?,
            previous_invocation_time: self.previous_invocation_time,
            next_invocation_time: self.next_invocation_time,
            error_report_configuration: self.error_report_configuration,
            target_destination: self.target_destination,
            last_run_status: self.last_run_status,
        })
    }
}
