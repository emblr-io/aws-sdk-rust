// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyClusterDbRevisionInput {
    /// <p>The unique identifier of a cluster whose database revision you want to modify.</p>
    /// <p>Example: <code>examplecluster</code></p>
    pub cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the database revision. You can retrieve this value from the response to the <code>DescribeClusterDbRevisions</code> request.</p>
    pub revision_target: ::std::option::Option<::std::string::String>,
}
impl ModifyClusterDbRevisionInput {
    /// <p>The unique identifier of a cluster whose database revision you want to modify.</p>
    /// <p>Example: <code>examplecluster</code></p>
    pub fn cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.cluster_identifier.as_deref()
    }
    /// <p>The identifier of the database revision. You can retrieve this value from the response to the <code>DescribeClusterDbRevisions</code> request.</p>
    pub fn revision_target(&self) -> ::std::option::Option<&str> {
        self.revision_target.as_deref()
    }
}
impl ModifyClusterDbRevisionInput {
    /// Creates a new builder-style object to manufacture [`ModifyClusterDbRevisionInput`](crate::operation::modify_cluster_db_revision::ModifyClusterDbRevisionInput).
    pub fn builder() -> crate::operation::modify_cluster_db_revision::builders::ModifyClusterDbRevisionInputBuilder {
        crate::operation::modify_cluster_db_revision::builders::ModifyClusterDbRevisionInputBuilder::default()
    }
}

/// A builder for [`ModifyClusterDbRevisionInput`](crate::operation::modify_cluster_db_revision::ModifyClusterDbRevisionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyClusterDbRevisionInputBuilder {
    pub(crate) cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) revision_target: ::std::option::Option<::std::string::String>,
}
impl ModifyClusterDbRevisionInputBuilder {
    /// <p>The unique identifier of a cluster whose database revision you want to modify.</p>
    /// <p>Example: <code>examplecluster</code></p>
    /// This field is required.
    pub fn cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of a cluster whose database revision you want to modify.</p>
    /// <p>Example: <code>examplecluster</code></p>
    pub fn set_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_identifier = input;
        self
    }
    /// <p>The unique identifier of a cluster whose database revision you want to modify.</p>
    /// <p>Example: <code>examplecluster</code></p>
    pub fn get_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_identifier
    }
    /// <p>The identifier of the database revision. You can retrieve this value from the response to the <code>DescribeClusterDbRevisions</code> request.</p>
    /// This field is required.
    pub fn revision_target(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_target = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the database revision. You can retrieve this value from the response to the <code>DescribeClusterDbRevisions</code> request.</p>
    pub fn set_revision_target(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_target = input;
        self
    }
    /// <p>The identifier of the database revision. You can retrieve this value from the response to the <code>DescribeClusterDbRevisions</code> request.</p>
    pub fn get_revision_target(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_target
    }
    /// Consumes the builder and constructs a [`ModifyClusterDbRevisionInput`](crate::operation::modify_cluster_db_revision::ModifyClusterDbRevisionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_cluster_db_revision::ModifyClusterDbRevisionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::modify_cluster_db_revision::ModifyClusterDbRevisionInput {
            cluster_identifier: self.cluster_identifier,
            revision_target: self.revision_target,
        })
    }
}
