// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The included place types.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReverseGeocodeFilter {
    /// <p>The included place types.</p>
    pub include_place_types: ::std::option::Option<::std::vec::Vec<crate::types::ReverseGeocodeFilterPlaceType>>,
}
impl ReverseGeocodeFilter {
    /// <p>The included place types.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.include_place_types.is_none()`.
    pub fn include_place_types(&self) -> &[crate::types::ReverseGeocodeFilterPlaceType] {
        self.include_place_types.as_deref().unwrap_or_default()
    }
}
impl ReverseGeocodeFilter {
    /// Creates a new builder-style object to manufacture [`ReverseGeocodeFilter`](crate::types::ReverseGeocodeFilter).
    pub fn builder() -> crate::types::builders::ReverseGeocodeFilterBuilder {
        crate::types::builders::ReverseGeocodeFilterBuilder::default()
    }
}

/// A builder for [`ReverseGeocodeFilter`](crate::types::ReverseGeocodeFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReverseGeocodeFilterBuilder {
    pub(crate) include_place_types: ::std::option::Option<::std::vec::Vec<crate::types::ReverseGeocodeFilterPlaceType>>,
}
impl ReverseGeocodeFilterBuilder {
    /// Appends an item to `include_place_types`.
    ///
    /// To override the contents of this collection use [`set_include_place_types`](Self::set_include_place_types).
    ///
    /// <p>The included place types.</p>
    pub fn include_place_types(mut self, input: crate::types::ReverseGeocodeFilterPlaceType) -> Self {
        let mut v = self.include_place_types.unwrap_or_default();
        v.push(input);
        self.include_place_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The included place types.</p>
    pub fn set_include_place_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReverseGeocodeFilterPlaceType>>) -> Self {
        self.include_place_types = input;
        self
    }
    /// <p>The included place types.</p>
    pub fn get_include_place_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReverseGeocodeFilterPlaceType>> {
        &self.include_place_types
    }
    /// Consumes the builder and constructs a [`ReverseGeocodeFilter`](crate::types::ReverseGeocodeFilter).
    pub fn build(self) -> crate::types::ReverseGeocodeFilter {
        crate::types::ReverseGeocodeFilter {
            include_place_types: self.include_place_types,
        }
    }
}
