// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object to override the original condition block of a calculated attribute.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ConditionOverrides {
    /// <p>The relative time period over which data is included in the aggregation for this override.</p>
    pub range: ::std::option::Option<crate::types::RangeOverride>,
}
impl ConditionOverrides {
    /// <p>The relative time period over which data is included in the aggregation for this override.</p>
    pub fn range(&self) -> ::std::option::Option<&crate::types::RangeOverride> {
        self.range.as_ref()
    }
}
impl ::std::fmt::Debug for ConditionOverrides {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ConditionOverrides");
        formatter.field("range", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl ConditionOverrides {
    /// Creates a new builder-style object to manufacture [`ConditionOverrides`](crate::types::ConditionOverrides).
    pub fn builder() -> crate::types::builders::ConditionOverridesBuilder {
        crate::types::builders::ConditionOverridesBuilder::default()
    }
}

/// A builder for [`ConditionOverrides`](crate::types::ConditionOverrides).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ConditionOverridesBuilder {
    pub(crate) range: ::std::option::Option<crate::types::RangeOverride>,
}
impl ConditionOverridesBuilder {
    /// <p>The relative time period over which data is included in the aggregation for this override.</p>
    pub fn range(mut self, input: crate::types::RangeOverride) -> Self {
        self.range = ::std::option::Option::Some(input);
        self
    }
    /// <p>The relative time period over which data is included in the aggregation for this override.</p>
    pub fn set_range(mut self, input: ::std::option::Option<crate::types::RangeOverride>) -> Self {
        self.range = input;
        self
    }
    /// <p>The relative time period over which data is included in the aggregation for this override.</p>
    pub fn get_range(&self) -> &::std::option::Option<crate::types::RangeOverride> {
        &self.range
    }
    /// Consumes the builder and constructs a [`ConditionOverrides`](crate::types::ConditionOverrides).
    pub fn build(self) -> crate::types::ConditionOverrides {
        crate::types::ConditionOverrides { range: self.range }
    }
}
impl ::std::fmt::Debug for ConditionOverridesBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ConditionOverridesBuilder");
        formatter.field("range", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
