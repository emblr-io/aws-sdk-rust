// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeMaintenanceWindowsInput {
    /// <p>Optional filters used to narrow down the scope of the returned maintenance windows. Supported filter keys are <code>Name</code> and <code>Enabled</code>. For example, <code>Name=MyMaintenanceWindow</code> and <code>Enabled=True</code>.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::MaintenanceWindowFilter>>,
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeMaintenanceWindowsInput {
    /// <p>Optional filters used to narrow down the scope of the returned maintenance windows. Supported filter keys are <code>Name</code> and <code>Enabled</code>. For example, <code>Name=MyMaintenanceWindow</code> and <code>Enabled=True</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::MaintenanceWindowFilter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeMaintenanceWindowsInput {
    /// Creates a new builder-style object to manufacture [`DescribeMaintenanceWindowsInput`](crate::operation::describe_maintenance_windows::DescribeMaintenanceWindowsInput).
    pub fn builder() -> crate::operation::describe_maintenance_windows::builders::DescribeMaintenanceWindowsInputBuilder {
        crate::operation::describe_maintenance_windows::builders::DescribeMaintenanceWindowsInputBuilder::default()
    }
}

/// A builder for [`DescribeMaintenanceWindowsInput`](crate::operation::describe_maintenance_windows::DescribeMaintenanceWindowsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeMaintenanceWindowsInputBuilder {
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::MaintenanceWindowFilter>>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeMaintenanceWindowsInputBuilder {
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>Optional filters used to narrow down the scope of the returned maintenance windows. Supported filter keys are <code>Name</code> and <code>Enabled</code>. For example, <code>Name=MyMaintenanceWindow</code> and <code>Enabled=True</code>.</p>
    pub fn filters(mut self, input: crate::types::MaintenanceWindowFilter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>Optional filters used to narrow down the scope of the returned maintenance windows. Supported filter keys are <code>Name</code> and <code>Enabled</code>. For example, <code>Name=MyMaintenanceWindow</code> and <code>Enabled=True</code>.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MaintenanceWindowFilter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>Optional filters used to narrow down the scope of the returned maintenance windows. Supported filter keys are <code>Name</code> and <code>Enabled</code>. For example, <code>Name=MyMaintenanceWindow</code> and <code>Enabled=True</code>.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MaintenanceWindowFilter>> {
        &self.filters
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeMaintenanceWindowsInput`](crate::operation::describe_maintenance_windows::DescribeMaintenanceWindowsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_maintenance_windows::DescribeMaintenanceWindowsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_maintenance_windows::DescribeMaintenanceWindowsInput {
            filters: self.filters,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
