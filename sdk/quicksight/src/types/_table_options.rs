// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The table options for a table visual.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TableOptions {
    /// <p>The orientation (vertical, horizontal) for a table.</p>
    pub orientation: ::std::option::Option<crate::types::TableOrientation>,
    /// <p>The table cell style of a table header.</p>
    pub header_style: ::std::option::Option<crate::types::TableCellStyle>,
    /// <p>The table cell style of table cells.</p>
    pub cell_style: ::std::option::Option<crate::types::TableCellStyle>,
    /// <p>The row alternate color options (widget status, row alternate colors) for a table.</p>
    pub row_alternate_color_options: ::std::option::Option<crate::types::RowAlternateColorOptions>,
}
impl TableOptions {
    /// <p>The orientation (vertical, horizontal) for a table.</p>
    pub fn orientation(&self) -> ::std::option::Option<&crate::types::TableOrientation> {
        self.orientation.as_ref()
    }
    /// <p>The table cell style of a table header.</p>
    pub fn header_style(&self) -> ::std::option::Option<&crate::types::TableCellStyle> {
        self.header_style.as_ref()
    }
    /// <p>The table cell style of table cells.</p>
    pub fn cell_style(&self) -> ::std::option::Option<&crate::types::TableCellStyle> {
        self.cell_style.as_ref()
    }
    /// <p>The row alternate color options (widget status, row alternate colors) for a table.</p>
    pub fn row_alternate_color_options(&self) -> ::std::option::Option<&crate::types::RowAlternateColorOptions> {
        self.row_alternate_color_options.as_ref()
    }
}
impl TableOptions {
    /// Creates a new builder-style object to manufacture [`TableOptions`](crate::types::TableOptions).
    pub fn builder() -> crate::types::builders::TableOptionsBuilder {
        crate::types::builders::TableOptionsBuilder::default()
    }
}

/// A builder for [`TableOptions`](crate::types::TableOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TableOptionsBuilder {
    pub(crate) orientation: ::std::option::Option<crate::types::TableOrientation>,
    pub(crate) header_style: ::std::option::Option<crate::types::TableCellStyle>,
    pub(crate) cell_style: ::std::option::Option<crate::types::TableCellStyle>,
    pub(crate) row_alternate_color_options: ::std::option::Option<crate::types::RowAlternateColorOptions>,
}
impl TableOptionsBuilder {
    /// <p>The orientation (vertical, horizontal) for a table.</p>
    pub fn orientation(mut self, input: crate::types::TableOrientation) -> Self {
        self.orientation = ::std::option::Option::Some(input);
        self
    }
    /// <p>The orientation (vertical, horizontal) for a table.</p>
    pub fn set_orientation(mut self, input: ::std::option::Option<crate::types::TableOrientation>) -> Self {
        self.orientation = input;
        self
    }
    /// <p>The orientation (vertical, horizontal) for a table.</p>
    pub fn get_orientation(&self) -> &::std::option::Option<crate::types::TableOrientation> {
        &self.orientation
    }
    /// <p>The table cell style of a table header.</p>
    pub fn header_style(mut self, input: crate::types::TableCellStyle) -> Self {
        self.header_style = ::std::option::Option::Some(input);
        self
    }
    /// <p>The table cell style of a table header.</p>
    pub fn set_header_style(mut self, input: ::std::option::Option<crate::types::TableCellStyle>) -> Self {
        self.header_style = input;
        self
    }
    /// <p>The table cell style of a table header.</p>
    pub fn get_header_style(&self) -> &::std::option::Option<crate::types::TableCellStyle> {
        &self.header_style
    }
    /// <p>The table cell style of table cells.</p>
    pub fn cell_style(mut self, input: crate::types::TableCellStyle) -> Self {
        self.cell_style = ::std::option::Option::Some(input);
        self
    }
    /// <p>The table cell style of table cells.</p>
    pub fn set_cell_style(mut self, input: ::std::option::Option<crate::types::TableCellStyle>) -> Self {
        self.cell_style = input;
        self
    }
    /// <p>The table cell style of table cells.</p>
    pub fn get_cell_style(&self) -> &::std::option::Option<crate::types::TableCellStyle> {
        &self.cell_style
    }
    /// <p>The row alternate color options (widget status, row alternate colors) for a table.</p>
    pub fn row_alternate_color_options(mut self, input: crate::types::RowAlternateColorOptions) -> Self {
        self.row_alternate_color_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The row alternate color options (widget status, row alternate colors) for a table.</p>
    pub fn set_row_alternate_color_options(mut self, input: ::std::option::Option<crate::types::RowAlternateColorOptions>) -> Self {
        self.row_alternate_color_options = input;
        self
    }
    /// <p>The row alternate color options (widget status, row alternate colors) for a table.</p>
    pub fn get_row_alternate_color_options(&self) -> &::std::option::Option<crate::types::RowAlternateColorOptions> {
        &self.row_alternate_color_options
    }
    /// Consumes the builder and constructs a [`TableOptions`](crate::types::TableOptions).
    pub fn build(self) -> crate::types::TableOptions {
        crate::types::TableOptions {
            orientation: self.orientation,
            header_style: self.header_style,
            cell_style: self.cell_style,
            row_alternate_color_options: self.row_alternate_color_options,
        }
    }
}
