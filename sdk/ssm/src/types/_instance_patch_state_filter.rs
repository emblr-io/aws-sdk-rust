// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines a filter used in <code>DescribeInstancePatchStatesForPatchGroup</code> to scope down the information returned by the API.</p>
/// <p><b>Example</b>: To filter for all managed nodes in a patch group having more than three patches with a <code>FailedCount</code> status, use the following for the filter:</p>
/// <ul>
/// <li>
/// <p>Value for <code>Key</code>: <code>FailedCount</code></p></li>
/// <li>
/// <p>Value for <code>Type</code>: <code>GreaterThan</code></p></li>
/// <li>
/// <p>Value for <code>Values</code>: <code>3</code></p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InstancePatchStateFilter {
    /// <p>The key for the filter. Supported values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>InstalledCount</code></p></li>
    /// <li>
    /// <p><code>InstalledOtherCount</code></p></li>
    /// <li>
    /// <p><code>InstalledPendingRebootCount</code></p></li>
    /// <li>
    /// <p><code>InstalledRejectedCount</code></p></li>
    /// <li>
    /// <p><code>MissingCount</code></p></li>
    /// <li>
    /// <p><code>FailedCount</code></p></li>
    /// <li>
    /// <p><code>UnreportedNotApplicableCount</code></p></li>
    /// <li>
    /// <p><code>NotApplicableCount</code></p></li>
    /// </ul>
    pub key: ::std::string::String,
    /// <p>The value for the filter. Must be an integer greater than or equal to 0.</p>
    pub values: ::std::vec::Vec<::std::string::String>,
    /// <p>The type of comparison that should be performed for the value.</p>
    pub r#type: crate::types::InstancePatchStateOperatorType,
}
impl InstancePatchStateFilter {
    /// <p>The key for the filter. Supported values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>InstalledCount</code></p></li>
    /// <li>
    /// <p><code>InstalledOtherCount</code></p></li>
    /// <li>
    /// <p><code>InstalledPendingRebootCount</code></p></li>
    /// <li>
    /// <p><code>InstalledRejectedCount</code></p></li>
    /// <li>
    /// <p><code>MissingCount</code></p></li>
    /// <li>
    /// <p><code>FailedCount</code></p></li>
    /// <li>
    /// <p><code>UnreportedNotApplicableCount</code></p></li>
    /// <li>
    /// <p><code>NotApplicableCount</code></p></li>
    /// </ul>
    pub fn key(&self) -> &str {
        use std::ops::Deref;
        self.key.deref()
    }
    /// <p>The value for the filter. Must be an integer greater than or equal to 0.</p>
    pub fn values(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.values.deref()
    }
    /// <p>The type of comparison that should be performed for the value.</p>
    pub fn r#type(&self) -> &crate::types::InstancePatchStateOperatorType {
        &self.r#type
    }
}
impl InstancePatchStateFilter {
    /// Creates a new builder-style object to manufacture [`InstancePatchStateFilter`](crate::types::InstancePatchStateFilter).
    pub fn builder() -> crate::types::builders::InstancePatchStateFilterBuilder {
        crate::types::builders::InstancePatchStateFilterBuilder::default()
    }
}

/// A builder for [`InstancePatchStateFilter`](crate::types::InstancePatchStateFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InstancePatchStateFilterBuilder {
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) r#type: ::std::option::Option<crate::types::InstancePatchStateOperatorType>,
}
impl InstancePatchStateFilterBuilder {
    /// <p>The key for the filter. Supported values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>InstalledCount</code></p></li>
    /// <li>
    /// <p><code>InstalledOtherCount</code></p></li>
    /// <li>
    /// <p><code>InstalledPendingRebootCount</code></p></li>
    /// <li>
    /// <p><code>InstalledRejectedCount</code></p></li>
    /// <li>
    /// <p><code>MissingCount</code></p></li>
    /// <li>
    /// <p><code>FailedCount</code></p></li>
    /// <li>
    /// <p><code>UnreportedNotApplicableCount</code></p></li>
    /// <li>
    /// <p><code>NotApplicableCount</code></p></li>
    /// </ul>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key for the filter. Supported values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>InstalledCount</code></p></li>
    /// <li>
    /// <p><code>InstalledOtherCount</code></p></li>
    /// <li>
    /// <p><code>InstalledPendingRebootCount</code></p></li>
    /// <li>
    /// <p><code>InstalledRejectedCount</code></p></li>
    /// <li>
    /// <p><code>MissingCount</code></p></li>
    /// <li>
    /// <p><code>FailedCount</code></p></li>
    /// <li>
    /// <p><code>UnreportedNotApplicableCount</code></p></li>
    /// <li>
    /// <p><code>NotApplicableCount</code></p></li>
    /// </ul>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The key for the filter. Supported values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>InstalledCount</code></p></li>
    /// <li>
    /// <p><code>InstalledOtherCount</code></p></li>
    /// <li>
    /// <p><code>InstalledPendingRebootCount</code></p></li>
    /// <li>
    /// <p><code>InstalledRejectedCount</code></p></li>
    /// <li>
    /// <p><code>MissingCount</code></p></li>
    /// <li>
    /// <p><code>FailedCount</code></p></li>
    /// <li>
    /// <p><code>UnreportedNotApplicableCount</code></p></li>
    /// <li>
    /// <p><code>NotApplicableCount</code></p></li>
    /// </ul>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>The value for the filter. Must be an integer greater than or equal to 0.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The value for the filter. Must be an integer greater than or equal to 0.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>The value for the filter. Must be an integer greater than or equal to 0.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// <p>The type of comparison that should be performed for the value.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::InstancePatchStateOperatorType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of comparison that should be performed for the value.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::InstancePatchStateOperatorType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of comparison that should be performed for the value.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::InstancePatchStateOperatorType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`InstancePatchStateFilter`](crate::types::InstancePatchStateFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`key`](crate::types::builders::InstancePatchStateFilterBuilder::key)
    /// - [`values`](crate::types::builders::InstancePatchStateFilterBuilder::values)
    /// - [`r#type`](crate::types::builders::InstancePatchStateFilterBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::InstancePatchStateFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::InstancePatchStateFilter {
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building InstancePatchStateFilter",
                )
            })?,
            values: self.values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "values",
                    "values was not specified but it is required when building InstancePatchStateFilter",
                )
            })?,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building InstancePatchStateFilter",
                )
            })?,
        })
    }
}
