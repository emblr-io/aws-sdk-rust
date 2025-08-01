// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A set of filters by which to return Recovery Instances.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeRecoveryInstancesRequestFilters {
    /// <p>An array of Recovery Instance IDs that should be returned. An empty array means all Recovery Instances.</p>
    pub recovery_instance_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>An array of Source Server IDs for which associated Recovery Instances should be returned.</p>
    pub source_server_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeRecoveryInstancesRequestFilters {
    /// <p>An array of Recovery Instance IDs that should be returned. An empty array means all Recovery Instances.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.recovery_instance_ids.is_none()`.
    pub fn recovery_instance_ids(&self) -> &[::std::string::String] {
        self.recovery_instance_ids.as_deref().unwrap_or_default()
    }
    /// <p>An array of Source Server IDs for which associated Recovery Instances should be returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.source_server_ids.is_none()`.
    pub fn source_server_ids(&self) -> &[::std::string::String] {
        self.source_server_ids.as_deref().unwrap_or_default()
    }
}
impl DescribeRecoveryInstancesRequestFilters {
    /// Creates a new builder-style object to manufacture [`DescribeRecoveryInstancesRequestFilters`](crate::types::DescribeRecoveryInstancesRequestFilters).
    pub fn builder() -> crate::types::builders::DescribeRecoveryInstancesRequestFiltersBuilder {
        crate::types::builders::DescribeRecoveryInstancesRequestFiltersBuilder::default()
    }
}

/// A builder for [`DescribeRecoveryInstancesRequestFilters`](crate::types::DescribeRecoveryInstancesRequestFilters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeRecoveryInstancesRequestFiltersBuilder {
    pub(crate) recovery_instance_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) source_server_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeRecoveryInstancesRequestFiltersBuilder {
    /// Appends an item to `recovery_instance_ids`.
    ///
    /// To override the contents of this collection use [`set_recovery_instance_ids`](Self::set_recovery_instance_ids).
    ///
    /// <p>An array of Recovery Instance IDs that should be returned. An empty array means all Recovery Instances.</p>
    pub fn recovery_instance_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.recovery_instance_ids.unwrap_or_default();
        v.push(input.into());
        self.recovery_instance_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of Recovery Instance IDs that should be returned. An empty array means all Recovery Instances.</p>
    pub fn set_recovery_instance_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.recovery_instance_ids = input;
        self
    }
    /// <p>An array of Recovery Instance IDs that should be returned. An empty array means all Recovery Instances.</p>
    pub fn get_recovery_instance_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.recovery_instance_ids
    }
    /// Appends an item to `source_server_ids`.
    ///
    /// To override the contents of this collection use [`set_source_server_ids`](Self::set_source_server_ids).
    ///
    /// <p>An array of Source Server IDs for which associated Recovery Instances should be returned.</p>
    pub fn source_server_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.source_server_ids.unwrap_or_default();
        v.push(input.into());
        self.source_server_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of Source Server IDs for which associated Recovery Instances should be returned.</p>
    pub fn set_source_server_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.source_server_ids = input;
        self
    }
    /// <p>An array of Source Server IDs for which associated Recovery Instances should be returned.</p>
    pub fn get_source_server_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.source_server_ids
    }
    /// Consumes the builder and constructs a [`DescribeRecoveryInstancesRequestFilters`](crate::types::DescribeRecoveryInstancesRequestFilters).
    pub fn build(self) -> crate::types::DescribeRecoveryInstancesRequestFilters {
        crate::types::DescribeRecoveryInstancesRequestFilters {
            recovery_instance_ids: self.recovery_instance_ids,
            source_server_ids: self.source_server_ids,
        }
    }
}
