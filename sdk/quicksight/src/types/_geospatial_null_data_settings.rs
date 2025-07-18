// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The properties for the visualization of null data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GeospatialNullDataSettings {
    /// <p>The symbol style for null data.</p>
    pub symbol_style: ::std::option::Option<crate::types::GeospatialNullSymbolStyle>,
}
impl GeospatialNullDataSettings {
    /// <p>The symbol style for null data.</p>
    pub fn symbol_style(&self) -> ::std::option::Option<&crate::types::GeospatialNullSymbolStyle> {
        self.symbol_style.as_ref()
    }
}
impl GeospatialNullDataSettings {
    /// Creates a new builder-style object to manufacture [`GeospatialNullDataSettings`](crate::types::GeospatialNullDataSettings).
    pub fn builder() -> crate::types::builders::GeospatialNullDataSettingsBuilder {
        crate::types::builders::GeospatialNullDataSettingsBuilder::default()
    }
}

/// A builder for [`GeospatialNullDataSettings`](crate::types::GeospatialNullDataSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GeospatialNullDataSettingsBuilder {
    pub(crate) symbol_style: ::std::option::Option<crate::types::GeospatialNullSymbolStyle>,
}
impl GeospatialNullDataSettingsBuilder {
    /// <p>The symbol style for null data.</p>
    /// This field is required.
    pub fn symbol_style(mut self, input: crate::types::GeospatialNullSymbolStyle) -> Self {
        self.symbol_style = ::std::option::Option::Some(input);
        self
    }
    /// <p>The symbol style for null data.</p>
    pub fn set_symbol_style(mut self, input: ::std::option::Option<crate::types::GeospatialNullSymbolStyle>) -> Self {
        self.symbol_style = input;
        self
    }
    /// <p>The symbol style for null data.</p>
    pub fn get_symbol_style(&self) -> &::std::option::Option<crate::types::GeospatialNullSymbolStyle> {
        &self.symbol_style
    }
    /// Consumes the builder and constructs a [`GeospatialNullDataSettings`](crate::types::GeospatialNullDataSettings).
    pub fn build(self) -> crate::types::GeospatialNullDataSettings {
        crate::types::GeospatialNullDataSettings {
            symbol_style: self.symbol_style,
        }
    }
}
