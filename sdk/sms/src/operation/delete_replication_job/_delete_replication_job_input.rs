// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteReplicationJobInput {
    /// <p>The ID of the replication job.</p>
    pub replication_job_id: ::std::option::Option<::std::string::String>,
}
impl DeleteReplicationJobInput {
    /// <p>The ID of the replication job.</p>
    pub fn replication_job_id(&self) -> ::std::option::Option<&str> {
        self.replication_job_id.as_deref()
    }
}
impl DeleteReplicationJobInput {
    /// Creates a new builder-style object to manufacture [`DeleteReplicationJobInput`](crate::operation::delete_replication_job::DeleteReplicationJobInput).
    pub fn builder() -> crate::operation::delete_replication_job::builders::DeleteReplicationJobInputBuilder {
        crate::operation::delete_replication_job::builders::DeleteReplicationJobInputBuilder::default()
    }
}

/// A builder for [`DeleteReplicationJobInput`](crate::operation::delete_replication_job::DeleteReplicationJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteReplicationJobInputBuilder {
    pub(crate) replication_job_id: ::std::option::Option<::std::string::String>,
}
impl DeleteReplicationJobInputBuilder {
    /// <p>The ID of the replication job.</p>
    /// This field is required.
    pub fn replication_job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the replication job.</p>
    pub fn set_replication_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_job_id = input;
        self
    }
    /// <p>The ID of the replication job.</p>
    pub fn get_replication_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_job_id
    }
    /// Consumes the builder and constructs a [`DeleteReplicationJobInput`](crate::operation::delete_replication_job::DeleteReplicationJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_replication_job::DeleteReplicationJobInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_replication_job::DeleteReplicationJobInput {
            replication_job_id: self.replication_job_id,
        })
    }
}
