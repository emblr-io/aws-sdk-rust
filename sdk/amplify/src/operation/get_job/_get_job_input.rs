// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request structure for the get job request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetJobInput {
    /// <p>The unique ID for an Amplify app.</p>
    pub app_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the branch to use for the job.</p>
    pub branch_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique ID for the job.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
}
impl GetJobInput {
    /// <p>The unique ID for an Amplify app.</p>
    pub fn app_id(&self) -> ::std::option::Option<&str> {
        self.app_id.as_deref()
    }
    /// <p>The name of the branch to use for the job.</p>
    pub fn branch_name(&self) -> ::std::option::Option<&str> {
        self.branch_name.as_deref()
    }
    /// <p>The unique ID for the job.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
}
impl GetJobInput {
    /// Creates a new builder-style object to manufacture [`GetJobInput`](crate::operation::get_job::GetJobInput).
    pub fn builder() -> crate::operation::get_job::builders::GetJobInputBuilder {
        crate::operation::get_job::builders::GetJobInputBuilder::default()
    }
}

/// A builder for [`GetJobInput`](crate::operation::get_job::GetJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetJobInputBuilder {
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) branch_name: ::std::option::Option<::std::string::String>,
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
}
impl GetJobInputBuilder {
    /// <p>The unique ID for an Amplify app.</p>
    /// This field is required.
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID for an Amplify app.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The unique ID for an Amplify app.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// <p>The name of the branch to use for the job.</p>
    /// This field is required.
    pub fn branch_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.branch_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the branch to use for the job.</p>
    pub fn set_branch_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.branch_name = input;
        self
    }
    /// <p>The name of the branch to use for the job.</p>
    pub fn get_branch_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.branch_name
    }
    /// <p>The unique ID for the job.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID for the job.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The unique ID for the job.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// Consumes the builder and constructs a [`GetJobInput`](crate::operation::get_job::GetJobInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_job::GetJobInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_job::GetJobInput {
            app_id: self.app_id,
            branch_name: self.branch_name,
            job_id: self.job_id,
        })
    }
}
