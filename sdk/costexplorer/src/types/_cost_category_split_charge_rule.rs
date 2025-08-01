// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Use the split charge rule to split the cost of one Cost Category value across several other target values.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CostCategorySplitChargeRule {
    /// <p>The Cost Category value that you want to split. That value can't be used as a source or a target in other split charge rules. To indicate uncategorized costs, you can use an empty string as the source.</p>
    pub source: ::std::string::String,
    /// <p>The Cost Category values that you want to split costs across. These values can't be used as a source in other split charge rules.</p>
    pub targets: ::std::vec::Vec<::std::string::String>,
    /// <p>The method that's used to define how to split your source costs across your targets.</p>
    /// <p><code>Proportional</code> - Allocates charges across your targets based on the proportional weighted cost of each target.</p>
    /// <p><code>Fixed</code> - Allocates charges across your targets based on your defined allocation percentage.</p>
    /// <p>&gt;<code>Even</code> - Allocates costs evenly across all targets.</p>
    pub method: crate::types::CostCategorySplitChargeMethod,
    /// <p>The parameters for a split charge method. This is only required for the <code>FIXED</code> method.</p>
    pub parameters: ::std::option::Option<::std::vec::Vec<crate::types::CostCategorySplitChargeRuleParameter>>,
}
impl CostCategorySplitChargeRule {
    /// <p>The Cost Category value that you want to split. That value can't be used as a source or a target in other split charge rules. To indicate uncategorized costs, you can use an empty string as the source.</p>
    pub fn source(&self) -> &str {
        use std::ops::Deref;
        self.source.deref()
    }
    /// <p>The Cost Category values that you want to split costs across. These values can't be used as a source in other split charge rules.</p>
    pub fn targets(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.targets.deref()
    }
    /// <p>The method that's used to define how to split your source costs across your targets.</p>
    /// <p><code>Proportional</code> - Allocates charges across your targets based on the proportional weighted cost of each target.</p>
    /// <p><code>Fixed</code> - Allocates charges across your targets based on your defined allocation percentage.</p>
    /// <p>&gt;<code>Even</code> - Allocates costs evenly across all targets.</p>
    pub fn method(&self) -> &crate::types::CostCategorySplitChargeMethod {
        &self.method
    }
    /// <p>The parameters for a split charge method. This is only required for the <code>FIXED</code> method.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.parameters.is_none()`.
    pub fn parameters(&self) -> &[crate::types::CostCategorySplitChargeRuleParameter] {
        self.parameters.as_deref().unwrap_or_default()
    }
}
impl CostCategorySplitChargeRule {
    /// Creates a new builder-style object to manufacture [`CostCategorySplitChargeRule`](crate::types::CostCategorySplitChargeRule).
    pub fn builder() -> crate::types::builders::CostCategorySplitChargeRuleBuilder {
        crate::types::builders::CostCategorySplitChargeRuleBuilder::default()
    }
}

/// A builder for [`CostCategorySplitChargeRule`](crate::types::CostCategorySplitChargeRule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CostCategorySplitChargeRuleBuilder {
    pub(crate) source: ::std::option::Option<::std::string::String>,
    pub(crate) targets: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) method: ::std::option::Option<crate::types::CostCategorySplitChargeMethod>,
    pub(crate) parameters: ::std::option::Option<::std::vec::Vec<crate::types::CostCategorySplitChargeRuleParameter>>,
}
impl CostCategorySplitChargeRuleBuilder {
    /// <p>The Cost Category value that you want to split. That value can't be used as a source or a target in other split charge rules. To indicate uncategorized costs, you can use an empty string as the source.</p>
    /// This field is required.
    pub fn source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Cost Category value that you want to split. That value can't be used as a source or a target in other split charge rules. To indicate uncategorized costs, you can use an empty string as the source.</p>
    pub fn set_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source = input;
        self
    }
    /// <p>The Cost Category value that you want to split. That value can't be used as a source or a target in other split charge rules. To indicate uncategorized costs, you can use an empty string as the source.</p>
    pub fn get_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.source
    }
    /// Appends an item to `targets`.
    ///
    /// To override the contents of this collection use [`set_targets`](Self::set_targets).
    ///
    /// <p>The Cost Category values that you want to split costs across. These values can't be used as a source in other split charge rules.</p>
    pub fn targets(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.targets.unwrap_or_default();
        v.push(input.into());
        self.targets = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Cost Category values that you want to split costs across. These values can't be used as a source in other split charge rules.</p>
    pub fn set_targets(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.targets = input;
        self
    }
    /// <p>The Cost Category values that you want to split costs across. These values can't be used as a source in other split charge rules.</p>
    pub fn get_targets(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.targets
    }
    /// <p>The method that's used to define how to split your source costs across your targets.</p>
    /// <p><code>Proportional</code> - Allocates charges across your targets based on the proportional weighted cost of each target.</p>
    /// <p><code>Fixed</code> - Allocates charges across your targets based on your defined allocation percentage.</p>
    /// <p>&gt;<code>Even</code> - Allocates costs evenly across all targets.</p>
    /// This field is required.
    pub fn method(mut self, input: crate::types::CostCategorySplitChargeMethod) -> Self {
        self.method = ::std::option::Option::Some(input);
        self
    }
    /// <p>The method that's used to define how to split your source costs across your targets.</p>
    /// <p><code>Proportional</code> - Allocates charges across your targets based on the proportional weighted cost of each target.</p>
    /// <p><code>Fixed</code> - Allocates charges across your targets based on your defined allocation percentage.</p>
    /// <p>&gt;<code>Even</code> - Allocates costs evenly across all targets.</p>
    pub fn set_method(mut self, input: ::std::option::Option<crate::types::CostCategorySplitChargeMethod>) -> Self {
        self.method = input;
        self
    }
    /// <p>The method that's used to define how to split your source costs across your targets.</p>
    /// <p><code>Proportional</code> - Allocates charges across your targets based on the proportional weighted cost of each target.</p>
    /// <p><code>Fixed</code> - Allocates charges across your targets based on your defined allocation percentage.</p>
    /// <p>&gt;<code>Even</code> - Allocates costs evenly across all targets.</p>
    pub fn get_method(&self) -> &::std::option::Option<crate::types::CostCategorySplitChargeMethod> {
        &self.method
    }
    /// Appends an item to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>The parameters for a split charge method. This is only required for the <code>FIXED</code> method.</p>
    pub fn parameters(mut self, input: crate::types::CostCategorySplitChargeRuleParameter) -> Self {
        let mut v = self.parameters.unwrap_or_default();
        v.push(input);
        self.parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The parameters for a split charge method. This is only required for the <code>FIXED</code> method.</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CostCategorySplitChargeRuleParameter>>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>The parameters for a split charge method. This is only required for the <code>FIXED</code> method.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CostCategorySplitChargeRuleParameter>> {
        &self.parameters
    }
    /// Consumes the builder and constructs a [`CostCategorySplitChargeRule`](crate::types::CostCategorySplitChargeRule).
    /// This method will fail if any of the following fields are not set:
    /// - [`source`](crate::types::builders::CostCategorySplitChargeRuleBuilder::source)
    /// - [`targets`](crate::types::builders::CostCategorySplitChargeRuleBuilder::targets)
    /// - [`method`](crate::types::builders::CostCategorySplitChargeRuleBuilder::method)
    pub fn build(self) -> ::std::result::Result<crate::types::CostCategorySplitChargeRule, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CostCategorySplitChargeRule {
            source: self.source.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "source",
                    "source was not specified but it is required when building CostCategorySplitChargeRule",
                )
            })?,
            targets: self.targets.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "targets",
                    "targets was not specified but it is required when building CostCategorySplitChargeRule",
                )
            })?,
            method: self.method.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "method",
                    "method was not specified but it is required when building CostCategorySplitChargeRule",
                )
            })?,
            parameters: self.parameters,
        })
    }
}
