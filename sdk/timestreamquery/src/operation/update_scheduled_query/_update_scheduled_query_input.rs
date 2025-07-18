// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateScheduledQueryInput {
    /// <p>ARN of the scheuled query.</p>
    pub scheduled_query_arn: ::std::option::Option<::std::string::String>,
    /// <p>State of the scheduled query.</p>
    pub state: ::std::option::Option<crate::types::ScheduledQueryState>,
}
impl UpdateScheduledQueryInput {
    /// <p>ARN of the scheuled query.</p>
    pub fn scheduled_query_arn(&self) -> ::std::option::Option<&str> {
        self.scheduled_query_arn.as_deref()
    }
    /// <p>State of the scheduled query.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::ScheduledQueryState> {
        self.state.as_ref()
    }
}
impl UpdateScheduledQueryInput {
    /// Creates a new builder-style object to manufacture [`UpdateScheduledQueryInput`](crate::operation::update_scheduled_query::UpdateScheduledQueryInput).
    pub fn builder() -> crate::operation::update_scheduled_query::builders::UpdateScheduledQueryInputBuilder {
        crate::operation::update_scheduled_query::builders::UpdateScheduledQueryInputBuilder::default()
    }
}

/// A builder for [`UpdateScheduledQueryInput`](crate::operation::update_scheduled_query::UpdateScheduledQueryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateScheduledQueryInputBuilder {
    pub(crate) scheduled_query_arn: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::ScheduledQueryState>,
}
impl UpdateScheduledQueryInputBuilder {
    /// <p>ARN of the scheuled query.</p>
    /// This field is required.
    pub fn scheduled_query_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scheduled_query_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of the scheuled query.</p>
    pub fn set_scheduled_query_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scheduled_query_arn = input;
        self
    }
    /// <p>ARN of the scheuled query.</p>
    pub fn get_scheduled_query_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.scheduled_query_arn
    }
    /// <p>State of the scheduled query.</p>
    /// This field is required.
    pub fn state(mut self, input: crate::types::ScheduledQueryState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>State of the scheduled query.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::ScheduledQueryState>) -> Self {
        self.state = input;
        self
    }
    /// <p>State of the scheduled query.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::ScheduledQueryState> {
        &self.state
    }
    /// Consumes the builder and constructs a [`UpdateScheduledQueryInput`](crate::operation::update_scheduled_query::UpdateScheduledQueryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_scheduled_query::UpdateScheduledQueryInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_scheduled_query::UpdateScheduledQueryInput {
            scheduled_query_arn: self.scheduled_query_arn,
            state: self.state,
        })
    }
}
