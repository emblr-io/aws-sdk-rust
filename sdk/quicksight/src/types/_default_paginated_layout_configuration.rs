// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The options that determine the default settings for a paginated layout configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DefaultPaginatedLayoutConfiguration {
    /// <p>The options that determine the default settings for a section-based layout configuration.</p>
    pub section_based: ::std::option::Option<crate::types::DefaultSectionBasedLayoutConfiguration>,
}
impl DefaultPaginatedLayoutConfiguration {
    /// <p>The options that determine the default settings for a section-based layout configuration.</p>
    pub fn section_based(&self) -> ::std::option::Option<&crate::types::DefaultSectionBasedLayoutConfiguration> {
        self.section_based.as_ref()
    }
}
impl DefaultPaginatedLayoutConfiguration {
    /// Creates a new builder-style object to manufacture [`DefaultPaginatedLayoutConfiguration`](crate::types::DefaultPaginatedLayoutConfiguration).
    pub fn builder() -> crate::types::builders::DefaultPaginatedLayoutConfigurationBuilder {
        crate::types::builders::DefaultPaginatedLayoutConfigurationBuilder::default()
    }
}

/// A builder for [`DefaultPaginatedLayoutConfiguration`](crate::types::DefaultPaginatedLayoutConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DefaultPaginatedLayoutConfigurationBuilder {
    pub(crate) section_based: ::std::option::Option<crate::types::DefaultSectionBasedLayoutConfiguration>,
}
impl DefaultPaginatedLayoutConfigurationBuilder {
    /// <p>The options that determine the default settings for a section-based layout configuration.</p>
    pub fn section_based(mut self, input: crate::types::DefaultSectionBasedLayoutConfiguration) -> Self {
        self.section_based = ::std::option::Option::Some(input);
        self
    }
    /// <p>The options that determine the default settings for a section-based layout configuration.</p>
    pub fn set_section_based(mut self, input: ::std::option::Option<crate::types::DefaultSectionBasedLayoutConfiguration>) -> Self {
        self.section_based = input;
        self
    }
    /// <p>The options that determine the default settings for a section-based layout configuration.</p>
    pub fn get_section_based(&self) -> &::std::option::Option<crate::types::DefaultSectionBasedLayoutConfiguration> {
        &self.section_based
    }
    /// Consumes the builder and constructs a [`DefaultPaginatedLayoutConfiguration`](crate::types::DefaultPaginatedLayoutConfiguration).
    pub fn build(self) -> crate::types::DefaultPaginatedLayoutConfiguration {
        crate::types::DefaultPaginatedLayoutConfiguration {
            section_based: self.section_based,
        }
    }
}
