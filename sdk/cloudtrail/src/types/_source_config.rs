// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains configuration information about the channel.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SourceConfig {
    /// <p>Specifies whether the channel applies to a single Region or to all Regions.</p>
    pub apply_to_all_regions: ::std::option::Option<bool>,
    /// <p>The advanced event selectors that are configured for the channel.</p>
    pub advanced_event_selectors: ::std::option::Option<::std::vec::Vec<crate::types::AdvancedEventSelector>>,
}
impl SourceConfig {
    /// <p>Specifies whether the channel applies to a single Region or to all Regions.</p>
    pub fn apply_to_all_regions(&self) -> ::std::option::Option<bool> {
        self.apply_to_all_regions
    }
    /// <p>The advanced event selectors that are configured for the channel.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.advanced_event_selectors.is_none()`.
    pub fn advanced_event_selectors(&self) -> &[crate::types::AdvancedEventSelector] {
        self.advanced_event_selectors.as_deref().unwrap_or_default()
    }
}
impl SourceConfig {
    /// Creates a new builder-style object to manufacture [`SourceConfig`](crate::types::SourceConfig).
    pub fn builder() -> crate::types::builders::SourceConfigBuilder {
        crate::types::builders::SourceConfigBuilder::default()
    }
}

/// A builder for [`SourceConfig`](crate::types::SourceConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SourceConfigBuilder {
    pub(crate) apply_to_all_regions: ::std::option::Option<bool>,
    pub(crate) advanced_event_selectors: ::std::option::Option<::std::vec::Vec<crate::types::AdvancedEventSelector>>,
}
impl SourceConfigBuilder {
    /// <p>Specifies whether the channel applies to a single Region or to all Regions.</p>
    pub fn apply_to_all_regions(mut self, input: bool) -> Self {
        self.apply_to_all_regions = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the channel applies to a single Region or to all Regions.</p>
    pub fn set_apply_to_all_regions(mut self, input: ::std::option::Option<bool>) -> Self {
        self.apply_to_all_regions = input;
        self
    }
    /// <p>Specifies whether the channel applies to a single Region or to all Regions.</p>
    pub fn get_apply_to_all_regions(&self) -> &::std::option::Option<bool> {
        &self.apply_to_all_regions
    }
    /// Appends an item to `advanced_event_selectors`.
    ///
    /// To override the contents of this collection use [`set_advanced_event_selectors`](Self::set_advanced_event_selectors).
    ///
    /// <p>The advanced event selectors that are configured for the channel.</p>
    pub fn advanced_event_selectors(mut self, input: crate::types::AdvancedEventSelector) -> Self {
        let mut v = self.advanced_event_selectors.unwrap_or_default();
        v.push(input);
        self.advanced_event_selectors = ::std::option::Option::Some(v);
        self
    }
    /// <p>The advanced event selectors that are configured for the channel.</p>
    pub fn set_advanced_event_selectors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AdvancedEventSelector>>) -> Self {
        self.advanced_event_selectors = input;
        self
    }
    /// <p>The advanced event selectors that are configured for the channel.</p>
    pub fn get_advanced_event_selectors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AdvancedEventSelector>> {
        &self.advanced_event_selectors
    }
    /// Consumes the builder and constructs a [`SourceConfig`](crate::types::SourceConfig).
    pub fn build(self) -> crate::types::SourceConfig {
        crate::types::SourceConfig {
            apply_to_all_regions: self.apply_to_all_regions,
            advanced_event_selectors: self.advanced_event_selectors,
        }
    }
}
