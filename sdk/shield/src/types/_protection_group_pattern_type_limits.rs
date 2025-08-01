// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Limits settings by pattern type in the protection groups for your subscription.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProtectionGroupPatternTypeLimits {
    /// <p>Limits settings on protection groups with arbitrary pattern type.</p>
    pub arbitrary_pattern_limits: ::std::option::Option<crate::types::ProtectionGroupArbitraryPatternLimits>,
}
impl ProtectionGroupPatternTypeLimits {
    /// <p>Limits settings on protection groups with arbitrary pattern type.</p>
    pub fn arbitrary_pattern_limits(&self) -> ::std::option::Option<&crate::types::ProtectionGroupArbitraryPatternLimits> {
        self.arbitrary_pattern_limits.as_ref()
    }
}
impl ProtectionGroupPatternTypeLimits {
    /// Creates a new builder-style object to manufacture [`ProtectionGroupPatternTypeLimits`](crate::types::ProtectionGroupPatternTypeLimits).
    pub fn builder() -> crate::types::builders::ProtectionGroupPatternTypeLimitsBuilder {
        crate::types::builders::ProtectionGroupPatternTypeLimitsBuilder::default()
    }
}

/// A builder for [`ProtectionGroupPatternTypeLimits`](crate::types::ProtectionGroupPatternTypeLimits).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProtectionGroupPatternTypeLimitsBuilder {
    pub(crate) arbitrary_pattern_limits: ::std::option::Option<crate::types::ProtectionGroupArbitraryPatternLimits>,
}
impl ProtectionGroupPatternTypeLimitsBuilder {
    /// <p>Limits settings on protection groups with arbitrary pattern type.</p>
    /// This field is required.
    pub fn arbitrary_pattern_limits(mut self, input: crate::types::ProtectionGroupArbitraryPatternLimits) -> Self {
        self.arbitrary_pattern_limits = ::std::option::Option::Some(input);
        self
    }
    /// <p>Limits settings on protection groups with arbitrary pattern type.</p>
    pub fn set_arbitrary_pattern_limits(mut self, input: ::std::option::Option<crate::types::ProtectionGroupArbitraryPatternLimits>) -> Self {
        self.arbitrary_pattern_limits = input;
        self
    }
    /// <p>Limits settings on protection groups with arbitrary pattern type.</p>
    pub fn get_arbitrary_pattern_limits(&self) -> &::std::option::Option<crate::types::ProtectionGroupArbitraryPatternLimits> {
        &self.arbitrary_pattern_limits
    }
    /// Consumes the builder and constructs a [`ProtectionGroupPatternTypeLimits`](crate::types::ProtectionGroupPatternTypeLimits).
    pub fn build(self) -> crate::types::ProtectionGroupPatternTypeLimits {
        crate::types::ProtectionGroupPatternTypeLimits {
            arbitrary_pattern_limits: self.arbitrary_pattern_limits,
        }
    }
}
