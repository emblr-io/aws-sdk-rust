// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p><b>\[Default policies only\]</b> Specifies a destination Region for cross-Region copy actions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CrossRegionCopyTarget {
    /// <p>The target Region, for example <code>us-east-1</code>.</p>
    pub target_region: ::std::option::Option<::std::string::String>,
}
impl CrossRegionCopyTarget {
    /// <p>The target Region, for example <code>us-east-1</code>.</p>
    pub fn target_region(&self) -> ::std::option::Option<&str> {
        self.target_region.as_deref()
    }
}
impl CrossRegionCopyTarget {
    /// Creates a new builder-style object to manufacture [`CrossRegionCopyTarget`](crate::types::CrossRegionCopyTarget).
    pub fn builder() -> crate::types::builders::CrossRegionCopyTargetBuilder {
        crate::types::builders::CrossRegionCopyTargetBuilder::default()
    }
}

/// A builder for [`CrossRegionCopyTarget`](crate::types::CrossRegionCopyTarget).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CrossRegionCopyTargetBuilder {
    pub(crate) target_region: ::std::option::Option<::std::string::String>,
}
impl CrossRegionCopyTargetBuilder {
    /// <p>The target Region, for example <code>us-east-1</code>.</p>
    pub fn target_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The target Region, for example <code>us-east-1</code>.</p>
    pub fn set_target_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_region = input;
        self
    }
    /// <p>The target Region, for example <code>us-east-1</code>.</p>
    pub fn get_target_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_region
    }
    /// Consumes the builder and constructs a [`CrossRegionCopyTarget`](crate::types::CrossRegionCopyTarget).
    pub fn build(self) -> crate::types::CrossRegionCopyTarget {
        crate::types::CrossRegionCopyTarget {
            target_region: self.target_region,
        }
    }
}
