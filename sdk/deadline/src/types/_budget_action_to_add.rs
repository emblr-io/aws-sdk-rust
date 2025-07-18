// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The budget action to add.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct BudgetActionToAdd {
    /// <p>The type of budget action to add.</p>
    pub r#type: crate::types::BudgetActionType,
    /// <p>The percentage threshold for the budget action to add.</p>
    pub threshold_percentage: f32,
    /// <p>A description for the budget action to add.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub description: ::std::option::Option<::std::string::String>,
}
impl BudgetActionToAdd {
    /// <p>The type of budget action to add.</p>
    pub fn r#type(&self) -> &crate::types::BudgetActionType {
        &self.r#type
    }
    /// <p>The percentage threshold for the budget action to add.</p>
    pub fn threshold_percentage(&self) -> f32 {
        self.threshold_percentage
    }
    /// <p>A description for the budget action to add.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl ::std::fmt::Debug for BudgetActionToAdd {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("BudgetActionToAdd");
        formatter.field("r#type", &self.r#type);
        formatter.field("threshold_percentage", &self.threshold_percentage);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl BudgetActionToAdd {
    /// Creates a new builder-style object to manufacture [`BudgetActionToAdd`](crate::types::BudgetActionToAdd).
    pub fn builder() -> crate::types::builders::BudgetActionToAddBuilder {
        crate::types::builders::BudgetActionToAddBuilder::default()
    }
}

/// A builder for [`BudgetActionToAdd`](crate::types::BudgetActionToAdd).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct BudgetActionToAddBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::BudgetActionType>,
    pub(crate) threshold_percentage: ::std::option::Option<f32>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl BudgetActionToAddBuilder {
    /// <p>The type of budget action to add.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::BudgetActionType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of budget action to add.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::BudgetActionType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of budget action to add.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::BudgetActionType> {
        &self.r#type
    }
    /// <p>The percentage threshold for the budget action to add.</p>
    /// This field is required.
    pub fn threshold_percentage(mut self, input: f32) -> Self {
        self.threshold_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The percentage threshold for the budget action to add.</p>
    pub fn set_threshold_percentage(mut self, input: ::std::option::Option<f32>) -> Self {
        self.threshold_percentage = input;
        self
    }
    /// <p>The percentage threshold for the budget action to add.</p>
    pub fn get_threshold_percentage(&self) -> &::std::option::Option<f32> {
        &self.threshold_percentage
    }
    /// <p>A description for the budget action to add.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the budget action to add.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the budget action to add.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`BudgetActionToAdd`](crate::types::BudgetActionToAdd).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::BudgetActionToAddBuilder::type)
    /// - [`threshold_percentage`](crate::types::builders::BudgetActionToAddBuilder::threshold_percentage)
    pub fn build(self) -> ::std::result::Result<crate::types::BudgetActionToAdd, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BudgetActionToAdd {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building BudgetActionToAdd",
                )
            })?,
            threshold_percentage: self.threshold_percentage.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "threshold_percentage",
                    "threshold_percentage was not specified but it is required when building BudgetActionToAdd",
                )
            })?,
            description: self.description,
        })
    }
}
impl ::std::fmt::Debug for BudgetActionToAddBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("BudgetActionToAddBuilder");
        formatter.field("r#type", &self.r#type);
        formatter.field("threshold_percentage", &self.threshold_percentage);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
