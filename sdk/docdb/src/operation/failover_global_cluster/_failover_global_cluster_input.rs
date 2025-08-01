// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FailoverGlobalClusterInput {
    /// <p>The identifier of the Amazon DocumentDB global cluster to apply this operation. The identifier is the unique key assigned by the user when the cluster is created. In other words, it's the name of the global cluster.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global cluster.</p></li>
    /// <li>
    /// <p>Minimum length of 1. Maximum length of 255.</p></li>
    /// </ul>
    /// <p>Pattern: <code>\[A-Za-z\]\[0-9A-Za-z-:._\]*</code></p>
    pub global_cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the secondary Amazon DocumentDB cluster that you want to promote to the primary for the global cluster. Use the Amazon Resource Name (ARN) for the identifier so that Amazon DocumentDB can locate the cluster in its Amazon Web Services region.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing secondary cluster.</p></li>
    /// <li>
    /// <p>Minimum length of 1. Maximum length of 255.</p></li>
    /// </ul>
    /// <p>Pattern: <code>\[A-Za-z\]\[0-9A-Za-z-:._\]*</code></p>
    pub target_db_cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether to allow data loss for this global cluster operation. Allowing data loss triggers a global failover operation.</p>
    /// <p>If you don't specify <code>AllowDataLoss</code>, the global cluster operation defaults to a switchover.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Can't be specified together with the <code>Switchover</code> parameter.</p></li>
    /// </ul>
    pub allow_data_loss: ::std::option::Option<bool>,
    /// <p>Specifies whether to switch over this global database cluster.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Can't be specified together with the <code>AllowDataLoss</code> parameter.</p></li>
    /// </ul>
    pub switchover: ::std::option::Option<bool>,
}
impl FailoverGlobalClusterInput {
    /// <p>The identifier of the Amazon DocumentDB global cluster to apply this operation. The identifier is the unique key assigned by the user when the cluster is created. In other words, it's the name of the global cluster.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global cluster.</p></li>
    /// <li>
    /// <p>Minimum length of 1. Maximum length of 255.</p></li>
    /// </ul>
    /// <p>Pattern: <code>\[A-Za-z\]\[0-9A-Za-z-:._\]*</code></p>
    pub fn global_cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.global_cluster_identifier.as_deref()
    }
    /// <p>The identifier of the secondary Amazon DocumentDB cluster that you want to promote to the primary for the global cluster. Use the Amazon Resource Name (ARN) for the identifier so that Amazon DocumentDB can locate the cluster in its Amazon Web Services region.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing secondary cluster.</p></li>
    /// <li>
    /// <p>Minimum length of 1. Maximum length of 255.</p></li>
    /// </ul>
    /// <p>Pattern: <code>\[A-Za-z\]\[0-9A-Za-z-:._\]*</code></p>
    pub fn target_db_cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.target_db_cluster_identifier.as_deref()
    }
    /// <p>Specifies whether to allow data loss for this global cluster operation. Allowing data loss triggers a global failover operation.</p>
    /// <p>If you don't specify <code>AllowDataLoss</code>, the global cluster operation defaults to a switchover.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Can't be specified together with the <code>Switchover</code> parameter.</p></li>
    /// </ul>
    pub fn allow_data_loss(&self) -> ::std::option::Option<bool> {
        self.allow_data_loss
    }
    /// <p>Specifies whether to switch over this global database cluster.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Can't be specified together with the <code>AllowDataLoss</code> parameter.</p></li>
    /// </ul>
    pub fn switchover(&self) -> ::std::option::Option<bool> {
        self.switchover
    }
}
impl FailoverGlobalClusterInput {
    /// Creates a new builder-style object to manufacture [`FailoverGlobalClusterInput`](crate::operation::failover_global_cluster::FailoverGlobalClusterInput).
    pub fn builder() -> crate::operation::failover_global_cluster::builders::FailoverGlobalClusterInputBuilder {
        crate::operation::failover_global_cluster::builders::FailoverGlobalClusterInputBuilder::default()
    }
}

/// A builder for [`FailoverGlobalClusterInput`](crate::operation::failover_global_cluster::FailoverGlobalClusterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FailoverGlobalClusterInputBuilder {
    pub(crate) global_cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) target_db_cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) allow_data_loss: ::std::option::Option<bool>,
    pub(crate) switchover: ::std::option::Option<bool>,
}
impl FailoverGlobalClusterInputBuilder {
    /// <p>The identifier of the Amazon DocumentDB global cluster to apply this operation. The identifier is the unique key assigned by the user when the cluster is created. In other words, it's the name of the global cluster.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global cluster.</p></li>
    /// <li>
    /// <p>Minimum length of 1. Maximum length of 255.</p></li>
    /// </ul>
    /// <p>Pattern: <code>\[A-Za-z\]\[0-9A-Za-z-:._\]*</code></p>
    /// This field is required.
    pub fn global_cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.global_cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon DocumentDB global cluster to apply this operation. The identifier is the unique key assigned by the user when the cluster is created. In other words, it's the name of the global cluster.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global cluster.</p></li>
    /// <li>
    /// <p>Minimum length of 1. Maximum length of 255.</p></li>
    /// </ul>
    /// <p>Pattern: <code>\[A-Za-z\]\[0-9A-Za-z-:._\]*</code></p>
    pub fn set_global_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.global_cluster_identifier = input;
        self
    }
    /// <p>The identifier of the Amazon DocumentDB global cluster to apply this operation. The identifier is the unique key assigned by the user when the cluster is created. In other words, it's the name of the global cluster.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global cluster.</p></li>
    /// <li>
    /// <p>Minimum length of 1. Maximum length of 255.</p></li>
    /// </ul>
    /// <p>Pattern: <code>\[A-Za-z\]\[0-9A-Za-z-:._\]*</code></p>
    pub fn get_global_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.global_cluster_identifier
    }
    /// <p>The identifier of the secondary Amazon DocumentDB cluster that you want to promote to the primary for the global cluster. Use the Amazon Resource Name (ARN) for the identifier so that Amazon DocumentDB can locate the cluster in its Amazon Web Services region.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing secondary cluster.</p></li>
    /// <li>
    /// <p>Minimum length of 1. Maximum length of 255.</p></li>
    /// </ul>
    /// <p>Pattern: <code>\[A-Za-z\]\[0-9A-Za-z-:._\]*</code></p>
    /// This field is required.
    pub fn target_db_cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_db_cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the secondary Amazon DocumentDB cluster that you want to promote to the primary for the global cluster. Use the Amazon Resource Name (ARN) for the identifier so that Amazon DocumentDB can locate the cluster in its Amazon Web Services region.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing secondary cluster.</p></li>
    /// <li>
    /// <p>Minimum length of 1. Maximum length of 255.</p></li>
    /// </ul>
    /// <p>Pattern: <code>\[A-Za-z\]\[0-9A-Za-z-:._\]*</code></p>
    pub fn set_target_db_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_db_cluster_identifier = input;
        self
    }
    /// <p>The identifier of the secondary Amazon DocumentDB cluster that you want to promote to the primary for the global cluster. Use the Amazon Resource Name (ARN) for the identifier so that Amazon DocumentDB can locate the cluster in its Amazon Web Services region.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing secondary cluster.</p></li>
    /// <li>
    /// <p>Minimum length of 1. Maximum length of 255.</p></li>
    /// </ul>
    /// <p>Pattern: <code>\[A-Za-z\]\[0-9A-Za-z-:._\]*</code></p>
    pub fn get_target_db_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_db_cluster_identifier
    }
    /// <p>Specifies whether to allow data loss for this global cluster operation. Allowing data loss triggers a global failover operation.</p>
    /// <p>If you don't specify <code>AllowDataLoss</code>, the global cluster operation defaults to a switchover.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Can't be specified together with the <code>Switchover</code> parameter.</p></li>
    /// </ul>
    pub fn allow_data_loss(mut self, input: bool) -> Self {
        self.allow_data_loss = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to allow data loss for this global cluster operation. Allowing data loss triggers a global failover operation.</p>
    /// <p>If you don't specify <code>AllowDataLoss</code>, the global cluster operation defaults to a switchover.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Can't be specified together with the <code>Switchover</code> parameter.</p></li>
    /// </ul>
    pub fn set_allow_data_loss(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allow_data_loss = input;
        self
    }
    /// <p>Specifies whether to allow data loss for this global cluster operation. Allowing data loss triggers a global failover operation.</p>
    /// <p>If you don't specify <code>AllowDataLoss</code>, the global cluster operation defaults to a switchover.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Can't be specified together with the <code>Switchover</code> parameter.</p></li>
    /// </ul>
    pub fn get_allow_data_loss(&self) -> &::std::option::Option<bool> {
        &self.allow_data_loss
    }
    /// <p>Specifies whether to switch over this global database cluster.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Can't be specified together with the <code>AllowDataLoss</code> parameter.</p></li>
    /// </ul>
    pub fn switchover(mut self, input: bool) -> Self {
        self.switchover = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to switch over this global database cluster.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Can't be specified together with the <code>AllowDataLoss</code> parameter.</p></li>
    /// </ul>
    pub fn set_switchover(mut self, input: ::std::option::Option<bool>) -> Self {
        self.switchover = input;
        self
    }
    /// <p>Specifies whether to switch over this global database cluster.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Can't be specified together with the <code>AllowDataLoss</code> parameter.</p></li>
    /// </ul>
    pub fn get_switchover(&self) -> &::std::option::Option<bool> {
        &self.switchover
    }
    /// Consumes the builder and constructs a [`FailoverGlobalClusterInput`](crate::operation::failover_global_cluster::FailoverGlobalClusterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::failover_global_cluster::FailoverGlobalClusterInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::failover_global_cluster::FailoverGlobalClusterInput {
            global_cluster_identifier: self.global_cluster_identifier,
            target_db_cluster_identifier: self.target_db_cluster_identifier,
            allow_data_loss: self.allow_data_loss,
            switchover: self.switchover,
        })
    }
}
