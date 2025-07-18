// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteReplicatorInput {
    /// <p>The current version of the replicator.</p>
    pub current_version: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the replicator to be deleted.</p>
    pub replicator_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteReplicatorInput {
    /// <p>The current version of the replicator.</p>
    pub fn current_version(&self) -> ::std::option::Option<&str> {
        self.current_version.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the replicator to be deleted.</p>
    pub fn replicator_arn(&self) -> ::std::option::Option<&str> {
        self.replicator_arn.as_deref()
    }
}
impl DeleteReplicatorInput {
    /// Creates a new builder-style object to manufacture [`DeleteReplicatorInput`](crate::operation::delete_replicator::DeleteReplicatorInput).
    pub fn builder() -> crate::operation::delete_replicator::builders::DeleteReplicatorInputBuilder {
        crate::operation::delete_replicator::builders::DeleteReplicatorInputBuilder::default()
    }
}

/// A builder for [`DeleteReplicatorInput`](crate::operation::delete_replicator::DeleteReplicatorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteReplicatorInputBuilder {
    pub(crate) current_version: ::std::option::Option<::std::string::String>,
    pub(crate) replicator_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteReplicatorInputBuilder {
    /// <p>The current version of the replicator.</p>
    pub fn current_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.current_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current version of the replicator.</p>
    pub fn set_current_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.current_version = input;
        self
    }
    /// <p>The current version of the replicator.</p>
    pub fn get_current_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.current_version
    }
    /// <p>The Amazon Resource Name (ARN) of the replicator to be deleted.</p>
    /// This field is required.
    pub fn replicator_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replicator_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replicator to be deleted.</p>
    pub fn set_replicator_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replicator_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replicator to be deleted.</p>
    pub fn get_replicator_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.replicator_arn
    }
    /// Consumes the builder and constructs a [`DeleteReplicatorInput`](crate::operation::delete_replicator::DeleteReplicatorInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_replicator::DeleteReplicatorInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_replicator::DeleteReplicatorInput {
            current_version: self.current_version,
            replicator_arn: self.replicator_arn,
        })
    }
}
