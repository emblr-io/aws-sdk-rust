// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResetJobBookmarkInput {
    /// <p>The name of the job in question.</p>
    pub job_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique run identifier associated with this job run.</p>
    pub run_id: ::std::option::Option<::std::string::String>,
}
impl ResetJobBookmarkInput {
    /// <p>The name of the job in question.</p>
    pub fn job_name(&self) -> ::std::option::Option<&str> {
        self.job_name.as_deref()
    }
    /// <p>The unique run identifier associated with this job run.</p>
    pub fn run_id(&self) -> ::std::option::Option<&str> {
        self.run_id.as_deref()
    }
}
impl ResetJobBookmarkInput {
    /// Creates a new builder-style object to manufacture [`ResetJobBookmarkInput`](crate::operation::reset_job_bookmark::ResetJobBookmarkInput).
    pub fn builder() -> crate::operation::reset_job_bookmark::builders::ResetJobBookmarkInputBuilder {
        crate::operation::reset_job_bookmark::builders::ResetJobBookmarkInputBuilder::default()
    }
}

/// A builder for [`ResetJobBookmarkInput`](crate::operation::reset_job_bookmark::ResetJobBookmarkInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResetJobBookmarkInputBuilder {
    pub(crate) job_name: ::std::option::Option<::std::string::String>,
    pub(crate) run_id: ::std::option::Option<::std::string::String>,
}
impl ResetJobBookmarkInputBuilder {
    /// <p>The name of the job in question.</p>
    /// This field is required.
    pub fn job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the job in question.</p>
    pub fn set_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_name = input;
        self
    }
    /// <p>The name of the job in question.</p>
    pub fn get_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_name
    }
    /// <p>The unique run identifier associated with this job run.</p>
    pub fn run_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.run_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique run identifier associated with this job run.</p>
    pub fn set_run_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.run_id = input;
        self
    }
    /// <p>The unique run identifier associated with this job run.</p>
    pub fn get_run_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.run_id
    }
    /// Consumes the builder and constructs a [`ResetJobBookmarkInput`](crate::operation::reset_job_bookmark::ResetJobBookmarkInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::reset_job_bookmark::ResetJobBookmarkInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::reset_job_bookmark::ResetJobBookmarkInput {
            job_name: self.job_name,
            run_id: self.run_id,
        })
    }
}
