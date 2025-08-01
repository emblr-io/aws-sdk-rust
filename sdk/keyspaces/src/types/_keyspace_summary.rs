// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the properties of a keyspace.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct KeyspaceSummary {
    /// <p>The name of the keyspace.</p>
    pub keyspace_name: ::std::string::String,
    /// <p>The unique identifier of the keyspace in the format of an Amazon Resource Name (ARN).</p>
    pub resource_arn: ::std::string::String,
    /// <p>This property specifies if a keyspace is a single Region keyspace or a multi-Region keyspace. The available values are <code>SINGLE_REGION</code> or <code>MULTI_REGION</code>.</p>
    pub replication_strategy: crate::types::Rs,
    /// <p>If the <code>replicationStrategy</code> of the keyspace is <code>MULTI_REGION</code>, a list of replication Regions is returned.</p>
    pub replication_regions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl KeyspaceSummary {
    /// <p>The name of the keyspace.</p>
    pub fn keyspace_name(&self) -> &str {
        use std::ops::Deref;
        self.keyspace_name.deref()
    }
    /// <p>The unique identifier of the keyspace in the format of an Amazon Resource Name (ARN).</p>
    pub fn resource_arn(&self) -> &str {
        use std::ops::Deref;
        self.resource_arn.deref()
    }
    /// <p>This property specifies if a keyspace is a single Region keyspace or a multi-Region keyspace. The available values are <code>SINGLE_REGION</code> or <code>MULTI_REGION</code>.</p>
    pub fn replication_strategy(&self) -> &crate::types::Rs {
        &self.replication_strategy
    }
    /// <p>If the <code>replicationStrategy</code> of the keyspace is <code>MULTI_REGION</code>, a list of replication Regions is returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.replication_regions.is_none()`.
    pub fn replication_regions(&self) -> &[::std::string::String] {
        self.replication_regions.as_deref().unwrap_or_default()
    }
}
impl KeyspaceSummary {
    /// Creates a new builder-style object to manufacture [`KeyspaceSummary`](crate::types::KeyspaceSummary).
    pub fn builder() -> crate::types::builders::KeyspaceSummaryBuilder {
        crate::types::builders::KeyspaceSummaryBuilder::default()
    }
}

/// A builder for [`KeyspaceSummary`](crate::types::KeyspaceSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct KeyspaceSummaryBuilder {
    pub(crate) keyspace_name: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) replication_strategy: ::std::option::Option<crate::types::Rs>,
    pub(crate) replication_regions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl KeyspaceSummaryBuilder {
    /// <p>The name of the keyspace.</p>
    /// This field is required.
    pub fn keyspace_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.keyspace_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the keyspace.</p>
    pub fn set_keyspace_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.keyspace_name = input;
        self
    }
    /// <p>The name of the keyspace.</p>
    pub fn get_keyspace_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.keyspace_name
    }
    /// <p>The unique identifier of the keyspace in the format of an Amazon Resource Name (ARN).</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the keyspace in the format of an Amazon Resource Name (ARN).</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The unique identifier of the keyspace in the format of an Amazon Resource Name (ARN).</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>This property specifies if a keyspace is a single Region keyspace or a multi-Region keyspace. The available values are <code>SINGLE_REGION</code> or <code>MULTI_REGION</code>.</p>
    /// This field is required.
    pub fn replication_strategy(mut self, input: crate::types::Rs) -> Self {
        self.replication_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>This property specifies if a keyspace is a single Region keyspace or a multi-Region keyspace. The available values are <code>SINGLE_REGION</code> or <code>MULTI_REGION</code>.</p>
    pub fn set_replication_strategy(mut self, input: ::std::option::Option<crate::types::Rs>) -> Self {
        self.replication_strategy = input;
        self
    }
    /// <p>This property specifies if a keyspace is a single Region keyspace or a multi-Region keyspace. The available values are <code>SINGLE_REGION</code> or <code>MULTI_REGION</code>.</p>
    pub fn get_replication_strategy(&self) -> &::std::option::Option<crate::types::Rs> {
        &self.replication_strategy
    }
    /// Appends an item to `replication_regions`.
    ///
    /// To override the contents of this collection use [`set_replication_regions`](Self::set_replication_regions).
    ///
    /// <p>If the <code>replicationStrategy</code> of the keyspace is <code>MULTI_REGION</code>, a list of replication Regions is returned.</p>
    pub fn replication_regions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.replication_regions.unwrap_or_default();
        v.push(input.into());
        self.replication_regions = ::std::option::Option::Some(v);
        self
    }
    /// <p>If the <code>replicationStrategy</code> of the keyspace is <code>MULTI_REGION</code>, a list of replication Regions is returned.</p>
    pub fn set_replication_regions(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.replication_regions = input;
        self
    }
    /// <p>If the <code>replicationStrategy</code> of the keyspace is <code>MULTI_REGION</code>, a list of replication Regions is returned.</p>
    pub fn get_replication_regions(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.replication_regions
    }
    /// Consumes the builder and constructs a [`KeyspaceSummary`](crate::types::KeyspaceSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`keyspace_name`](crate::types::builders::KeyspaceSummaryBuilder::keyspace_name)
    /// - [`resource_arn`](crate::types::builders::KeyspaceSummaryBuilder::resource_arn)
    /// - [`replication_strategy`](crate::types::builders::KeyspaceSummaryBuilder::replication_strategy)
    pub fn build(self) -> ::std::result::Result<crate::types::KeyspaceSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::KeyspaceSummary {
            keyspace_name: self.keyspace_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "keyspace_name",
                    "keyspace_name was not specified but it is required when building KeyspaceSummary",
                )
            })?,
            resource_arn: self.resource_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_arn",
                    "resource_arn was not specified but it is required when building KeyspaceSummary",
                )
            })?,
            replication_strategy: self.replication_strategy.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "replication_strategy",
                    "replication_strategy was not specified but it is required when building KeyspaceSummary",
                )
            })?,
            replication_regions: self.replication_regions,
        })
    }
}
