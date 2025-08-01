// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>One or more filters. Use a filter to return a more specific list of results.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ParameterStringFilter {
    /// <p>The name of the filter.</p>
    /// <p>The <code>ParameterStringFilter</code> object is used by the <code>DescribeParameters</code> and <code>GetParametersByPath</code> API operations. However, not all of the pattern values listed for <code>Key</code> can be used with both operations.</p>
    /// <p>For <code>DescribeParameters</code>, all of the listed patterns are valid except <code>Label</code>.</p>
    /// <p>For <code>GetParametersByPath</code>, the following patterns listed for <code>Key</code> aren't valid: <code>tag</code>, <code>DataType</code>, <code>Name</code>, <code>Path</code>, and <code>Tier</code>.</p>
    /// <p>For examples of Amazon Web Services CLI commands demonstrating valid parameter filter constructions, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-search.html">Searching for Systems Manager parameters</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub key: ::std::string::String,
    /// <p>For all filters used with <code>DescribeParameters</code>, valid options include <code>Equals</code> and <code>BeginsWith</code>. The <code>Name</code> filter additionally supports the <code>Contains</code> option. (Exception: For filters using the key <code>Path</code>, valid options include <code>Recursive</code> and <code>OneLevel</code>.)</p>
    /// <p>For filters used with <code>GetParametersByPath</code>, valid options include <code>Equals</code> and <code>BeginsWith</code>. (Exception: For filters using <code>Label</code> as the Key name, the only valid option is <code>Equals</code>.)</p>
    pub option: ::std::option::Option<::std::string::String>,
    /// <p>The value you want to search for.</p>
    pub values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ParameterStringFilter {
    /// <p>The name of the filter.</p>
    /// <p>The <code>ParameterStringFilter</code> object is used by the <code>DescribeParameters</code> and <code>GetParametersByPath</code> API operations. However, not all of the pattern values listed for <code>Key</code> can be used with both operations.</p>
    /// <p>For <code>DescribeParameters</code>, all of the listed patterns are valid except <code>Label</code>.</p>
    /// <p>For <code>GetParametersByPath</code>, the following patterns listed for <code>Key</code> aren't valid: <code>tag</code>, <code>DataType</code>, <code>Name</code>, <code>Path</code>, and <code>Tier</code>.</p>
    /// <p>For examples of Amazon Web Services CLI commands demonstrating valid parameter filter constructions, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-search.html">Searching for Systems Manager parameters</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn key(&self) -> &str {
        use std::ops::Deref;
        self.key.deref()
    }
    /// <p>For all filters used with <code>DescribeParameters</code>, valid options include <code>Equals</code> and <code>BeginsWith</code>. The <code>Name</code> filter additionally supports the <code>Contains</code> option. (Exception: For filters using the key <code>Path</code>, valid options include <code>Recursive</code> and <code>OneLevel</code>.)</p>
    /// <p>For filters used with <code>GetParametersByPath</code>, valid options include <code>Equals</code> and <code>BeginsWith</code>. (Exception: For filters using <code>Label</code> as the Key name, the only valid option is <code>Equals</code>.)</p>
    pub fn option(&self) -> ::std::option::Option<&str> {
        self.option.as_deref()
    }
    /// <p>The value you want to search for.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.values.is_none()`.
    pub fn values(&self) -> &[::std::string::String] {
        self.values.as_deref().unwrap_or_default()
    }
}
impl ParameterStringFilter {
    /// Creates a new builder-style object to manufacture [`ParameterStringFilter`](crate::types::ParameterStringFilter).
    pub fn builder() -> crate::types::builders::ParameterStringFilterBuilder {
        crate::types::builders::ParameterStringFilterBuilder::default()
    }
}

/// A builder for [`ParameterStringFilter`](crate::types::ParameterStringFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ParameterStringFilterBuilder {
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) option: ::std::option::Option<::std::string::String>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ParameterStringFilterBuilder {
    /// <p>The name of the filter.</p>
    /// <p>The <code>ParameterStringFilter</code> object is used by the <code>DescribeParameters</code> and <code>GetParametersByPath</code> API operations. However, not all of the pattern values listed for <code>Key</code> can be used with both operations.</p>
    /// <p>For <code>DescribeParameters</code>, all of the listed patterns are valid except <code>Label</code>.</p>
    /// <p>For <code>GetParametersByPath</code>, the following patterns listed for <code>Key</code> aren't valid: <code>tag</code>, <code>DataType</code>, <code>Name</code>, <code>Path</code>, and <code>Tier</code>.</p>
    /// <p>For examples of Amazon Web Services CLI commands demonstrating valid parameter filter constructions, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-search.html">Searching for Systems Manager parameters</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the filter.</p>
    /// <p>The <code>ParameterStringFilter</code> object is used by the <code>DescribeParameters</code> and <code>GetParametersByPath</code> API operations. However, not all of the pattern values listed for <code>Key</code> can be used with both operations.</p>
    /// <p>For <code>DescribeParameters</code>, all of the listed patterns are valid except <code>Label</code>.</p>
    /// <p>For <code>GetParametersByPath</code>, the following patterns listed for <code>Key</code> aren't valid: <code>tag</code>, <code>DataType</code>, <code>Name</code>, <code>Path</code>, and <code>Tier</code>.</p>
    /// <p>For examples of Amazon Web Services CLI commands demonstrating valid parameter filter constructions, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-search.html">Searching for Systems Manager parameters</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The name of the filter.</p>
    /// <p>The <code>ParameterStringFilter</code> object is used by the <code>DescribeParameters</code> and <code>GetParametersByPath</code> API operations. However, not all of the pattern values listed for <code>Key</code> can be used with both operations.</p>
    /// <p>For <code>DescribeParameters</code>, all of the listed patterns are valid except <code>Label</code>.</p>
    /// <p>For <code>GetParametersByPath</code>, the following patterns listed for <code>Key</code> aren't valid: <code>tag</code>, <code>DataType</code>, <code>Name</code>, <code>Path</code>, and <code>Tier</code>.</p>
    /// <p>For examples of Amazon Web Services CLI commands demonstrating valid parameter filter constructions, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-search.html">Searching for Systems Manager parameters</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>For all filters used with <code>DescribeParameters</code>, valid options include <code>Equals</code> and <code>BeginsWith</code>. The <code>Name</code> filter additionally supports the <code>Contains</code> option. (Exception: For filters using the key <code>Path</code>, valid options include <code>Recursive</code> and <code>OneLevel</code>.)</p>
    /// <p>For filters used with <code>GetParametersByPath</code>, valid options include <code>Equals</code> and <code>BeginsWith</code>. (Exception: For filters using <code>Label</code> as the Key name, the only valid option is <code>Equals</code>.)</p>
    pub fn option(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.option = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For all filters used with <code>DescribeParameters</code>, valid options include <code>Equals</code> and <code>BeginsWith</code>. The <code>Name</code> filter additionally supports the <code>Contains</code> option. (Exception: For filters using the key <code>Path</code>, valid options include <code>Recursive</code> and <code>OneLevel</code>.)</p>
    /// <p>For filters used with <code>GetParametersByPath</code>, valid options include <code>Equals</code> and <code>BeginsWith</code>. (Exception: For filters using <code>Label</code> as the Key name, the only valid option is <code>Equals</code>.)</p>
    pub fn set_option(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.option = input;
        self
    }
    /// <p>For all filters used with <code>DescribeParameters</code>, valid options include <code>Equals</code> and <code>BeginsWith</code>. The <code>Name</code> filter additionally supports the <code>Contains</code> option. (Exception: For filters using the key <code>Path</code>, valid options include <code>Recursive</code> and <code>OneLevel</code>.)</p>
    /// <p>For filters used with <code>GetParametersByPath</code>, valid options include <code>Equals</code> and <code>BeginsWith</code>. (Exception: For filters using <code>Label</code> as the Key name, the only valid option is <code>Equals</code>.)</p>
    pub fn get_option(&self) -> &::std::option::Option<::std::string::String> {
        &self.option
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>The value you want to search for.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The value you want to search for.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>The value you want to search for.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`ParameterStringFilter`](crate::types::ParameterStringFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`key`](crate::types::builders::ParameterStringFilterBuilder::key)
    pub fn build(self) -> ::std::result::Result<crate::types::ParameterStringFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ParameterStringFilter {
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building ParameterStringFilter",
                )
            })?,
            option: self.option,
            values: self.values,
        })
    }
}
