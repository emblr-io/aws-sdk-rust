// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents information about a job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Job {
    /// <p>The unique system-generated ID of the job.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>Other data about a job.</p>
    pub data: ::std::option::Option<crate::types::JobData>,
    /// <p>A system-generated random number that CodePipeline uses to ensure that the job is being worked on by only one job worker. Use this number in an <code>AcknowledgeJob</code> request.</p>
    pub nonce: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Amazon Web Services account to use when performing the job.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
}
impl Job {
    /// <p>The unique system-generated ID of the job.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>Other data about a job.</p>
    pub fn data(&self) -> ::std::option::Option<&crate::types::JobData> {
        self.data.as_ref()
    }
    /// <p>A system-generated random number that CodePipeline uses to ensure that the job is being worked on by only one job worker. Use this number in an <code>AcknowledgeJob</code> request.</p>
    pub fn nonce(&self) -> ::std::option::Option<&str> {
        self.nonce.as_deref()
    }
    /// <p>The ID of the Amazon Web Services account to use when performing the job.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
}
impl Job {
    /// Creates a new builder-style object to manufacture [`Job`](crate::types::Job).
    pub fn builder() -> crate::types::builders::JobBuilder {
        crate::types::builders::JobBuilder::default()
    }
}

/// A builder for [`Job`](crate::types::Job).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JobBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) data: ::std::option::Option<crate::types::JobData>,
    pub(crate) nonce: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
}
impl JobBuilder {
    /// <p>The unique system-generated ID of the job.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique system-generated ID of the job.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique system-generated ID of the job.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>Other data about a job.</p>
    pub fn data(mut self, input: crate::types::JobData) -> Self {
        self.data = ::std::option::Option::Some(input);
        self
    }
    /// <p>Other data about a job.</p>
    pub fn set_data(mut self, input: ::std::option::Option<crate::types::JobData>) -> Self {
        self.data = input;
        self
    }
    /// <p>Other data about a job.</p>
    pub fn get_data(&self) -> &::std::option::Option<crate::types::JobData> {
        &self.data
    }
    /// <p>A system-generated random number that CodePipeline uses to ensure that the job is being worked on by only one job worker. Use this number in an <code>AcknowledgeJob</code> request.</p>
    pub fn nonce(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.nonce = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A system-generated random number that CodePipeline uses to ensure that the job is being worked on by only one job worker. Use this number in an <code>AcknowledgeJob</code> request.</p>
    pub fn set_nonce(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.nonce = input;
        self
    }
    /// <p>A system-generated random number that CodePipeline uses to ensure that the job is being worked on by only one job worker. Use this number in an <code>AcknowledgeJob</code> request.</p>
    pub fn get_nonce(&self) -> &::std::option::Option<::std::string::String> {
        &self.nonce
    }
    /// <p>The ID of the Amazon Web Services account to use when performing the job.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account to use when performing the job.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account to use when performing the job.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// Consumes the builder and constructs a [`Job`](crate::types::Job).
    pub fn build(self) -> crate::types::Job {
        crate::types::Job {
            id: self.id,
            data: self.data,
            nonce: self.nonce,
            account_id: self.account_id,
        }
    }
}
