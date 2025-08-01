// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The information for a protect configuration rule set number override that meets a specified criteria.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProtectConfigurationRuleSetNumberOverrideFilterItem {
    /// <p>The name of the attribute to filter on.</p>
    pub name: crate::types::ProtectConfigurationRuleSetNumberOverrideFilterName,
    /// <p>An array values to filter for.</p>
    pub values: ::std::vec::Vec<::std::string::String>,
}
impl ProtectConfigurationRuleSetNumberOverrideFilterItem {
    /// <p>The name of the attribute to filter on.</p>
    pub fn name(&self) -> &crate::types::ProtectConfigurationRuleSetNumberOverrideFilterName {
        &self.name
    }
    /// <p>An array values to filter for.</p>
    pub fn values(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.values.deref()
    }
}
impl ProtectConfigurationRuleSetNumberOverrideFilterItem {
    /// Creates a new builder-style object to manufacture [`ProtectConfigurationRuleSetNumberOverrideFilterItem`](crate::types::ProtectConfigurationRuleSetNumberOverrideFilterItem).
    pub fn builder() -> crate::types::builders::ProtectConfigurationRuleSetNumberOverrideFilterItemBuilder {
        crate::types::builders::ProtectConfigurationRuleSetNumberOverrideFilterItemBuilder::default()
    }
}

/// A builder for [`ProtectConfigurationRuleSetNumberOverrideFilterItem`](crate::types::ProtectConfigurationRuleSetNumberOverrideFilterItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProtectConfigurationRuleSetNumberOverrideFilterItemBuilder {
    pub(crate) name: ::std::option::Option<crate::types::ProtectConfigurationRuleSetNumberOverrideFilterName>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ProtectConfigurationRuleSetNumberOverrideFilterItemBuilder {
    /// <p>The name of the attribute to filter on.</p>
    /// This field is required.
    pub fn name(mut self, input: crate::types::ProtectConfigurationRuleSetNumberOverrideFilterName) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the attribute to filter on.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::ProtectConfigurationRuleSetNumberOverrideFilterName>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the attribute to filter on.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::ProtectConfigurationRuleSetNumberOverrideFilterName> {
        &self.name
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>An array values to filter for.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array values to filter for.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>An array values to filter for.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`ProtectConfigurationRuleSetNumberOverrideFilterItem`](crate::types::ProtectConfigurationRuleSetNumberOverrideFilterItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::ProtectConfigurationRuleSetNumberOverrideFilterItemBuilder::name)
    /// - [`values`](crate::types::builders::ProtectConfigurationRuleSetNumberOverrideFilterItemBuilder::values)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::ProtectConfigurationRuleSetNumberOverrideFilterItem, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::types::ProtectConfigurationRuleSetNumberOverrideFilterItem {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building ProtectConfigurationRuleSetNumberOverrideFilterItem",
                )
            })?,
            values: self.values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "values",
                    "values was not specified but it is required when building ProtectConfigurationRuleSetNumberOverrideFilterItem",
                )
            })?,
        })
    }
}
