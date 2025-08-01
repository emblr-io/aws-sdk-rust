// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTriggersInput {
    /// <p>A continuation token, if this is a continuation call.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The name of the job to retrieve triggers for. The trigger that can start this job is returned, and if there is no such trigger, all triggers are returned.</p>
    pub dependent_job_name: ::std::option::Option<::std::string::String>,
    /// <p>The maximum size of the response.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl GetTriggersInput {
    /// <p>A continuation token, if this is a continuation call.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The name of the job to retrieve triggers for. The trigger that can start this job is returned, and if there is no such trigger, all triggers are returned.</p>
    pub fn dependent_job_name(&self) -> ::std::option::Option<&str> {
        self.dependent_job_name.as_deref()
    }
    /// <p>The maximum size of the response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl GetTriggersInput {
    /// Creates a new builder-style object to manufacture [`GetTriggersInput`](crate::operation::get_triggers::GetTriggersInput).
    pub fn builder() -> crate::operation::get_triggers::builders::GetTriggersInputBuilder {
        crate::operation::get_triggers::builders::GetTriggersInputBuilder::default()
    }
}

/// A builder for [`GetTriggersInput`](crate::operation::get_triggers::GetTriggersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTriggersInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) dependent_job_name: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl GetTriggersInputBuilder {
    /// <p>A continuation token, if this is a continuation call.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A continuation token, if this is a continuation call.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A continuation token, if this is a continuation call.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The name of the job to retrieve triggers for. The trigger that can start this job is returned, and if there is no such trigger, all triggers are returned.</p>
    pub fn dependent_job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dependent_job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the job to retrieve triggers for. The trigger that can start this job is returned, and if there is no such trigger, all triggers are returned.</p>
    pub fn set_dependent_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dependent_job_name = input;
        self
    }
    /// <p>The name of the job to retrieve triggers for. The trigger that can start this job is returned, and if there is no such trigger, all triggers are returned.</p>
    pub fn get_dependent_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.dependent_job_name
    }
    /// <p>The maximum size of the response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum size of the response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum size of the response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`GetTriggersInput`](crate::operation::get_triggers::GetTriggersInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_triggers::GetTriggersInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_triggers::GetTriggersInput {
            next_token: self.next_token,
            dependent_job_name: self.dependent_job_name,
            max_results: self.max_results,
        })
    }
}
