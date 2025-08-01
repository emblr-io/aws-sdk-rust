// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The scope configuration for a <code>FilterGroup</code>.</p>
/// <p>This is a union type structure. For this structure to be valid, only one of the attributes can be defined.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FilterScopeConfiguration {
    /// <p>The configuration for applying a filter to specific sheets.</p>
    pub selected_sheets: ::std::option::Option<crate::types::SelectedSheetsFilterScopeConfiguration>,
    /// <p>The configuration that applies a filter to all sheets. When you choose <code>AllSheets</code> as the value for a <code>FilterScopeConfiguration</code>, this filter is applied to all visuals of all sheets in an Analysis, Dashboard, or Template. The <code>AllSheetsFilterScopeConfiguration</code> is chosen.</p>
    pub all_sheets: ::std::option::Option<crate::types::AllSheetsFilterScopeConfiguration>,
}
impl FilterScopeConfiguration {
    /// <p>The configuration for applying a filter to specific sheets.</p>
    pub fn selected_sheets(&self) -> ::std::option::Option<&crate::types::SelectedSheetsFilterScopeConfiguration> {
        self.selected_sheets.as_ref()
    }
    /// <p>The configuration that applies a filter to all sheets. When you choose <code>AllSheets</code> as the value for a <code>FilterScopeConfiguration</code>, this filter is applied to all visuals of all sheets in an Analysis, Dashboard, or Template. The <code>AllSheetsFilterScopeConfiguration</code> is chosen.</p>
    pub fn all_sheets(&self) -> ::std::option::Option<&crate::types::AllSheetsFilterScopeConfiguration> {
        self.all_sheets.as_ref()
    }
}
impl FilterScopeConfiguration {
    /// Creates a new builder-style object to manufacture [`FilterScopeConfiguration`](crate::types::FilterScopeConfiguration).
    pub fn builder() -> crate::types::builders::FilterScopeConfigurationBuilder {
        crate::types::builders::FilterScopeConfigurationBuilder::default()
    }
}

/// A builder for [`FilterScopeConfiguration`](crate::types::FilterScopeConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FilterScopeConfigurationBuilder {
    pub(crate) selected_sheets: ::std::option::Option<crate::types::SelectedSheetsFilterScopeConfiguration>,
    pub(crate) all_sheets: ::std::option::Option<crate::types::AllSheetsFilterScopeConfiguration>,
}
impl FilterScopeConfigurationBuilder {
    /// <p>The configuration for applying a filter to specific sheets.</p>
    pub fn selected_sheets(mut self, input: crate::types::SelectedSheetsFilterScopeConfiguration) -> Self {
        self.selected_sheets = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for applying a filter to specific sheets.</p>
    pub fn set_selected_sheets(mut self, input: ::std::option::Option<crate::types::SelectedSheetsFilterScopeConfiguration>) -> Self {
        self.selected_sheets = input;
        self
    }
    /// <p>The configuration for applying a filter to specific sheets.</p>
    pub fn get_selected_sheets(&self) -> &::std::option::Option<crate::types::SelectedSheetsFilterScopeConfiguration> {
        &self.selected_sheets
    }
    /// <p>The configuration that applies a filter to all sheets. When you choose <code>AllSheets</code> as the value for a <code>FilterScopeConfiguration</code>, this filter is applied to all visuals of all sheets in an Analysis, Dashboard, or Template. The <code>AllSheetsFilterScopeConfiguration</code> is chosen.</p>
    pub fn all_sheets(mut self, input: crate::types::AllSheetsFilterScopeConfiguration) -> Self {
        self.all_sheets = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration that applies a filter to all sheets. When you choose <code>AllSheets</code> as the value for a <code>FilterScopeConfiguration</code>, this filter is applied to all visuals of all sheets in an Analysis, Dashboard, or Template. The <code>AllSheetsFilterScopeConfiguration</code> is chosen.</p>
    pub fn set_all_sheets(mut self, input: ::std::option::Option<crate::types::AllSheetsFilterScopeConfiguration>) -> Self {
        self.all_sheets = input;
        self
    }
    /// <p>The configuration that applies a filter to all sheets. When you choose <code>AllSheets</code> as the value for a <code>FilterScopeConfiguration</code>, this filter is applied to all visuals of all sheets in an Analysis, Dashboard, or Template. The <code>AllSheetsFilterScopeConfiguration</code> is chosen.</p>
    pub fn get_all_sheets(&self) -> &::std::option::Option<crate::types::AllSheetsFilterScopeConfiguration> {
        &self.all_sheets
    }
    /// Consumes the builder and constructs a [`FilterScopeConfiguration`](crate::types::FilterScopeConfiguration).
    pub fn build(self) -> crate::types::FilterScopeConfiguration {
        crate::types::FilterScopeConfiguration {
            selected_sheets: self.selected_sheets,
            all_sheets: self.all_sheets,
        }
    }
}
