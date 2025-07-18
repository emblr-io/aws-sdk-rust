// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration for a <code>TableVisual</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TableConfiguration {
    /// <p>The field wells of the visual.</p>
    pub field_wells: ::std::option::Option<crate::types::TableFieldWells>,
    /// <p>The sort configuration for a <code>TableVisual</code>.</p>
    pub sort_configuration: ::std::option::Option<crate::types::TableSortConfiguration>,
    /// <p>The table options for a table visual.</p>
    pub table_options: ::std::option::Option<crate::types::TableOptions>,
    /// <p>The total options for a table visual.</p>
    pub total_options: ::std::option::Option<crate::types::TotalOptions>,
    /// <p>The field options for a table visual.</p>
    pub field_options: ::std::option::Option<crate::types::TableFieldOptions>,
    /// <p>The paginated report options for a table visual.</p>
    pub paginated_report_options: ::std::option::Option<crate::types::TablePaginatedReportOptions>,
    /// <p>A collection of inline visualizations to display within a chart.</p>
    pub table_inline_visualizations: ::std::option::Option<::std::vec::Vec<crate::types::TableInlineVisualization>>,
    /// <p>The general visual interactions setup for a visual.</p>
    pub interactions: ::std::option::Option<crate::types::VisualInteractionOptions>,
}
impl TableConfiguration {
    /// <p>The field wells of the visual.</p>
    pub fn field_wells(&self) -> ::std::option::Option<&crate::types::TableFieldWells> {
        self.field_wells.as_ref()
    }
    /// <p>The sort configuration for a <code>TableVisual</code>.</p>
    pub fn sort_configuration(&self) -> ::std::option::Option<&crate::types::TableSortConfiguration> {
        self.sort_configuration.as_ref()
    }
    /// <p>The table options for a table visual.</p>
    pub fn table_options(&self) -> ::std::option::Option<&crate::types::TableOptions> {
        self.table_options.as_ref()
    }
    /// <p>The total options for a table visual.</p>
    pub fn total_options(&self) -> ::std::option::Option<&crate::types::TotalOptions> {
        self.total_options.as_ref()
    }
    /// <p>The field options for a table visual.</p>
    pub fn field_options(&self) -> ::std::option::Option<&crate::types::TableFieldOptions> {
        self.field_options.as_ref()
    }
    /// <p>The paginated report options for a table visual.</p>
    pub fn paginated_report_options(&self) -> ::std::option::Option<&crate::types::TablePaginatedReportOptions> {
        self.paginated_report_options.as_ref()
    }
    /// <p>A collection of inline visualizations to display within a chart.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.table_inline_visualizations.is_none()`.
    pub fn table_inline_visualizations(&self) -> &[crate::types::TableInlineVisualization] {
        self.table_inline_visualizations.as_deref().unwrap_or_default()
    }
    /// <p>The general visual interactions setup for a visual.</p>
    pub fn interactions(&self) -> ::std::option::Option<&crate::types::VisualInteractionOptions> {
        self.interactions.as_ref()
    }
}
impl TableConfiguration {
    /// Creates a new builder-style object to manufacture [`TableConfiguration`](crate::types::TableConfiguration).
    pub fn builder() -> crate::types::builders::TableConfigurationBuilder {
        crate::types::builders::TableConfigurationBuilder::default()
    }
}

/// A builder for [`TableConfiguration`](crate::types::TableConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TableConfigurationBuilder {
    pub(crate) field_wells: ::std::option::Option<crate::types::TableFieldWells>,
    pub(crate) sort_configuration: ::std::option::Option<crate::types::TableSortConfiguration>,
    pub(crate) table_options: ::std::option::Option<crate::types::TableOptions>,
    pub(crate) total_options: ::std::option::Option<crate::types::TotalOptions>,
    pub(crate) field_options: ::std::option::Option<crate::types::TableFieldOptions>,
    pub(crate) paginated_report_options: ::std::option::Option<crate::types::TablePaginatedReportOptions>,
    pub(crate) table_inline_visualizations: ::std::option::Option<::std::vec::Vec<crate::types::TableInlineVisualization>>,
    pub(crate) interactions: ::std::option::Option<crate::types::VisualInteractionOptions>,
}
impl TableConfigurationBuilder {
    /// <p>The field wells of the visual.</p>
    pub fn field_wells(mut self, input: crate::types::TableFieldWells) -> Self {
        self.field_wells = ::std::option::Option::Some(input);
        self
    }
    /// <p>The field wells of the visual.</p>
    pub fn set_field_wells(mut self, input: ::std::option::Option<crate::types::TableFieldWells>) -> Self {
        self.field_wells = input;
        self
    }
    /// <p>The field wells of the visual.</p>
    pub fn get_field_wells(&self) -> &::std::option::Option<crate::types::TableFieldWells> {
        &self.field_wells
    }
    /// <p>The sort configuration for a <code>TableVisual</code>.</p>
    pub fn sort_configuration(mut self, input: crate::types::TableSortConfiguration) -> Self {
        self.sort_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sort configuration for a <code>TableVisual</code>.</p>
    pub fn set_sort_configuration(mut self, input: ::std::option::Option<crate::types::TableSortConfiguration>) -> Self {
        self.sort_configuration = input;
        self
    }
    /// <p>The sort configuration for a <code>TableVisual</code>.</p>
    pub fn get_sort_configuration(&self) -> &::std::option::Option<crate::types::TableSortConfiguration> {
        &self.sort_configuration
    }
    /// <p>The table options for a table visual.</p>
    pub fn table_options(mut self, input: crate::types::TableOptions) -> Self {
        self.table_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The table options for a table visual.</p>
    pub fn set_table_options(mut self, input: ::std::option::Option<crate::types::TableOptions>) -> Self {
        self.table_options = input;
        self
    }
    /// <p>The table options for a table visual.</p>
    pub fn get_table_options(&self) -> &::std::option::Option<crate::types::TableOptions> {
        &self.table_options
    }
    /// <p>The total options for a table visual.</p>
    pub fn total_options(mut self, input: crate::types::TotalOptions) -> Self {
        self.total_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total options for a table visual.</p>
    pub fn set_total_options(mut self, input: ::std::option::Option<crate::types::TotalOptions>) -> Self {
        self.total_options = input;
        self
    }
    /// <p>The total options for a table visual.</p>
    pub fn get_total_options(&self) -> &::std::option::Option<crate::types::TotalOptions> {
        &self.total_options
    }
    /// <p>The field options for a table visual.</p>
    pub fn field_options(mut self, input: crate::types::TableFieldOptions) -> Self {
        self.field_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The field options for a table visual.</p>
    pub fn set_field_options(mut self, input: ::std::option::Option<crate::types::TableFieldOptions>) -> Self {
        self.field_options = input;
        self
    }
    /// <p>The field options for a table visual.</p>
    pub fn get_field_options(&self) -> &::std::option::Option<crate::types::TableFieldOptions> {
        &self.field_options
    }
    /// <p>The paginated report options for a table visual.</p>
    pub fn paginated_report_options(mut self, input: crate::types::TablePaginatedReportOptions) -> Self {
        self.paginated_report_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The paginated report options for a table visual.</p>
    pub fn set_paginated_report_options(mut self, input: ::std::option::Option<crate::types::TablePaginatedReportOptions>) -> Self {
        self.paginated_report_options = input;
        self
    }
    /// <p>The paginated report options for a table visual.</p>
    pub fn get_paginated_report_options(&self) -> &::std::option::Option<crate::types::TablePaginatedReportOptions> {
        &self.paginated_report_options
    }
    /// Appends an item to `table_inline_visualizations`.
    ///
    /// To override the contents of this collection use [`set_table_inline_visualizations`](Self::set_table_inline_visualizations).
    ///
    /// <p>A collection of inline visualizations to display within a chart.</p>
    pub fn table_inline_visualizations(mut self, input: crate::types::TableInlineVisualization) -> Self {
        let mut v = self.table_inline_visualizations.unwrap_or_default();
        v.push(input);
        self.table_inline_visualizations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A collection of inline visualizations to display within a chart.</p>
    pub fn set_table_inline_visualizations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TableInlineVisualization>>) -> Self {
        self.table_inline_visualizations = input;
        self
    }
    /// <p>A collection of inline visualizations to display within a chart.</p>
    pub fn get_table_inline_visualizations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TableInlineVisualization>> {
        &self.table_inline_visualizations
    }
    /// <p>The general visual interactions setup for a visual.</p>
    pub fn interactions(mut self, input: crate::types::VisualInteractionOptions) -> Self {
        self.interactions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The general visual interactions setup for a visual.</p>
    pub fn set_interactions(mut self, input: ::std::option::Option<crate::types::VisualInteractionOptions>) -> Self {
        self.interactions = input;
        self
    }
    /// <p>The general visual interactions setup for a visual.</p>
    pub fn get_interactions(&self) -> &::std::option::Option<crate::types::VisualInteractionOptions> {
        &self.interactions
    }
    /// Consumes the builder and constructs a [`TableConfiguration`](crate::types::TableConfiguration).
    pub fn build(self) -> crate::types::TableConfiguration {
        crate::types::TableConfiguration {
            field_wells: self.field_wells,
            sort_configuration: self.sort_configuration,
            table_options: self.table_options,
            total_options: self.total_options,
            field_options: self.field_options,
            paginated_report_options: self.paginated_report_options,
            table_inline_visualizations: self.table_inline_visualizations,
            interactions: self.interactions,
        }
    }
}
