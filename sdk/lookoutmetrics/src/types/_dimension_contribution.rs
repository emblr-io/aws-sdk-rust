// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about a dimension that contributed to an anomaly.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DimensionContribution {
    /// <p>The name of the dimension.</p>
    pub dimension_name: ::std::option::Option<::std::string::String>,
    /// <p>A list of dimension values that contributed to the anomaly.</p>
    pub dimension_value_contribution_list: ::std::option::Option<::std::vec::Vec<crate::types::DimensionValueContribution>>,
}
impl DimensionContribution {
    /// <p>The name of the dimension.</p>
    pub fn dimension_name(&self) -> ::std::option::Option<&str> {
        self.dimension_name.as_deref()
    }
    /// <p>A list of dimension values that contributed to the anomaly.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dimension_value_contribution_list.is_none()`.
    pub fn dimension_value_contribution_list(&self) -> &[crate::types::DimensionValueContribution] {
        self.dimension_value_contribution_list.as_deref().unwrap_or_default()
    }
}
impl DimensionContribution {
    /// Creates a new builder-style object to manufacture [`DimensionContribution`](crate::types::DimensionContribution).
    pub fn builder() -> crate::types::builders::DimensionContributionBuilder {
        crate::types::builders::DimensionContributionBuilder::default()
    }
}

/// A builder for [`DimensionContribution`](crate::types::DimensionContribution).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DimensionContributionBuilder {
    pub(crate) dimension_name: ::std::option::Option<::std::string::String>,
    pub(crate) dimension_value_contribution_list: ::std::option::Option<::std::vec::Vec<crate::types::DimensionValueContribution>>,
}
impl DimensionContributionBuilder {
    /// <p>The name of the dimension.</p>
    pub fn dimension_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dimension_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the dimension.</p>
    pub fn set_dimension_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dimension_name = input;
        self
    }
    /// <p>The name of the dimension.</p>
    pub fn get_dimension_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.dimension_name
    }
    /// Appends an item to `dimension_value_contribution_list`.
    ///
    /// To override the contents of this collection use [`set_dimension_value_contribution_list`](Self::set_dimension_value_contribution_list).
    ///
    /// <p>A list of dimension values that contributed to the anomaly.</p>
    pub fn dimension_value_contribution_list(mut self, input: crate::types::DimensionValueContribution) -> Self {
        let mut v = self.dimension_value_contribution_list.unwrap_or_default();
        v.push(input);
        self.dimension_value_contribution_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of dimension values that contributed to the anomaly.</p>
    pub fn set_dimension_value_contribution_list(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::DimensionValueContribution>>,
    ) -> Self {
        self.dimension_value_contribution_list = input;
        self
    }
    /// <p>A list of dimension values that contributed to the anomaly.</p>
    pub fn get_dimension_value_contribution_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DimensionValueContribution>> {
        &self.dimension_value_contribution_list
    }
    /// Consumes the builder and constructs a [`DimensionContribution`](crate::types::DimensionContribution).
    pub fn build(self) -> crate::types::DimensionContribution {
        crate::types::DimensionContribution {
            dimension_name: self.dimension_name,
            dimension_value_contribution_list: self.dimension_value_contribution_list,
        }
    }
}
